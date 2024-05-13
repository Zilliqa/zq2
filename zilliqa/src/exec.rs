//! Manages execution of transactions on state.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    num::NonZeroU128,
    sync::Arc,
};

use alloy_primitives::{Address, U256};
use anyhow::{anyhow, Result};
use eth_trie::Trie;
use ethabi::Token;
use libp2p::PeerId;
use revm::{
    inspector_handle_register,
    primitives::{
        AccountInfo, BlockEnv, Bytecode, BytecodeState, ExecutionResult, HandlerCfg, Output,
        ResultAndState, SpecId, TransactTo, TxEnv, B256, KECCAK_EMPTY,
    },
    Database, Evm, Inspector,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, trace, warn};

use crate::{
    contracts,
    crypto::{Hash, NodePublicKey},
    eth_helpers::extract_revert_msg,
    inspector::{self, ScillaInspector},
    message::{Block, BlockHeader},
    precompiles::get_custom_precompiles,
    scilla,
    state::{contract_addr, Account, Contract, ScillaValue, State},
    time::SystemTime,
    transaction::{
        total_scilla_gas_price, EvmGas, Log, ScillaGas, ScillaParam, Transaction, TxZilliqa,
        VerifiedTransaction, ZilAmount,
    },
};

/// Data returned after applying a [Transaction] to [State].
pub struct TransactionApplyResult {
    /// Whether the transaction succeeded and the resulting state changes were persisted.
    pub success: bool,
    /// If the transaction was a contract creation, the address of the resulting contract.
    pub contract_address: Option<Address>,
    /// The logs emitted by the transaction execution.
    pub logs: Vec<Log>,
    /// The gas paid by the transaction
    pub gas_used: EvmGas,
    /// The output of the transaction execution. Note that Scilla calls cannot return data, so the output will always
    /// be empty.
    pub output: TransactionOutput,
    /// If the transaction was a call to a Scilla contract, whether the called contract accepted the ZIL sent to it.
    pub accepted: Option<bool>,
    /// Errors from calls to Scilla contracts. Indexed by the call depth of erroring contract.
    pub errors: BTreeMap<u64, Vec<ScillaError>>,
    /// Exceptions from calls to Scilla contracts.
    pub exceptions: Vec<ScillaException>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScillaError {
    CallFailed,
    CreateFailed,
    OutOfGas,
    InsufficientBalance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScillaException {
    pub line: u64,
    pub message: String,
}

impl From<scilla::Error> for ScillaException {
    fn from(e: scilla::Error) -> ScillaException {
        ScillaException {
            line: e.start_location.line,
            message: e.error_message,
        }
    }
}

// We need to define a custom error type for our [Database], which implements [Error].
#[derive(Debug)]
pub struct DatabaseError(anyhow::Error);

impl From<anyhow::Error> for DatabaseError {
    fn from(err: anyhow::Error) -> Self {
        DatabaseError(err)
    }
}

impl Display for DatabaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for DatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl Database for &State {
    type Error = DatabaseError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if !self.has_account(address)? {
            return Ok(None);
        }

        let account = self.get_account(address)?;
        let account_info = AccountInfo {
            balance: U256::from(account.balance),
            nonce: account.nonce,
            code_hash: KECCAK_EMPTY,
            code: Some(Bytecode {
                bytecode: account.contract.evm_code().unwrap_or_default().into(),
                state: BytecodeState::Raw,
            }),
        };

        Ok(Some(account_info))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let index = B256::new(index.to_be_bytes());

        let result = self.get_account_storage(address, index)?;

        Ok(U256::from_be_bytes(result.0))
    }

    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        // TODO
        Ok(B256::ZERO)
    }
}

pub const BLOCK_GAS_LIMIT: EvmGas = EvmGas(84_000_000);
/// The price per unit of [EvmGas].
pub const GAS_PRICE: u128 = 4761904800000;

const SCILLA_TRANSFER: ScillaGas = ScillaGas(50);
const SCILLA_INVOKE_CHECKER: ScillaGas = ScillaGas(100);
const SCILLA_INVOKE_RUNNER: ScillaGas = ScillaGas(300);

const SPEC_ID: SpecId = SpecId::SHANGHAI;

impl State {
    /// Used primarily during genesis to set up contracts for chain functionality.
    /// If override_address address is set, forces contract deployment to that addess.
    pub(crate) fn force_deploy_contract_evm(
        &mut self,
        creation_bytecode: Vec<u8>,
        override_address: Option<Address>,
    ) -> Result<Address> {
        let ResultAndState { result, mut state } = self.apply_transaction_evm(
            Address::ZERO,
            None,
            GAS_PRICE,
            BLOCK_GAS_LIMIT,
            0,
            creation_bytecode,
            None,
            0,
            BlockHeader::genesis(Hash::ZERO),
            inspector::noop(),
        )?;

        match result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(addr)),
                ..
            } => {
                let addr = if let Some(override_address) = override_address {
                    let override_address = Address::from(override_address.0);
                    let account = state
                        .remove(&addr)
                        .ok_or_else(|| anyhow!("deployment did not change the contract account"))?;
                    state.insert(override_address, account);
                    addr
                } else {
                    addr
                };

                self.apply_delta_evm(state)?;
                Ok(addr)
            }
            ExecutionResult::Success { .. } => {
                Err(anyhow!("deployment did not create a transaction"))
            }
            ExecutionResult::Revert { .. } => Err(anyhow!("deployment reverted")),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("deployment halted: {reason:?}")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_transaction_evm<I: for<'s> Inspector<&'s State>>(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u128,
        gas_limit: EvmGas,
        amount: u128,
        payload: Vec<u8>,
        nonce: Option<u64>,
        chain_id: u64,
        current_block: BlockHeader,
        inspector: I,
    ) -> Result<ResultAndState> {
        let mut evm = Evm::builder()
            .with_db(self)
            .with_block_env(BlockEnv {
                number: U256::from(current_block.number),
                coinbase: Address::ZERO,
                timestamp: U256::from(
                    current_block
                        .timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                gas_limit: U256::from(BLOCK_GAS_LIMIT.0),
                basefee: U256::from(GAS_PRICE),
                difficulty: U256::from(1),
                prevrandao: Some(B256::ZERO),
                blob_excess_gas_and_price: None,
            })
            .with_external_context(inspector)
            .with_handler_cfg(HandlerCfg { spec_id: SPEC_ID })
            .append_handler_register(inspector_handle_register)
            .modify_cfg_env(|c| {
                c.chain_id = chain_id;
                // We disable the balance check (which ensures the from account's balance is greater than the
                // transaction's `gas_price * gas_limit`), because Scilla transactions are often submitted with
                // overly high `gas_limit`s. This is probably because there is no gas estimation feature for Scilla
                // transactions.
                c.disable_balance_check = true;
            })
            .with_tx_env(TxEnv {
                caller: from_addr.0.into(),
                gas_limit: gas_limit.0,
                gas_price: U256::from(gas_price),
                transact_to: to_addr
                    .map(|a| TransactTo::call(a.0.into()))
                    .unwrap_or_else(TransactTo::create),
                value: U256::from(amount),
                data: payload.clone().into(),
                nonce,
                chain_id: Some(chain_id),
                access_list: vec![],
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: None,
            })
            .append_handler_register(|handler| {
                let precompiles = handler.pre_execution.load_precompiles();
                handler.pre_execution.load_precompiles = Arc::new(move || {
                    let mut precompiles = precompiles.clone();
                    precompiles.extend(get_custom_precompiles());
                    precompiles
                });
            })
            .build();

        let e = evm.transact()?;
        Ok(e)
    }

    fn apply_transaction_scilla(
        &mut self,
        from_addr: Address,
        current_block: BlockHeader,
        txn: TxZilliqa,
        inspector: impl ScillaInspector,
    ) -> Result<TransactionApplyResult> {
        let code = self
            .get_account(txn.to_addr)?
            .contract
            .scilla_code()
            .unwrap_or_default();

        let deposit = total_scilla_gas_price(txn.gas_limit, txn.gas_price);
        if let Some(result) = self.deduct_from_account(from_addr, deposit)? {
            return Ok(result);
        }

        let gas_limit = txn.gas_limit;
        let gas_price = txn.gas_price;

        let result = if txn.to_addr.is_zero() {
            self.scilla_create(from_addr, txn, current_block, inspector)
        } else if code.is_empty() {
            self.scilla_transfer_to_eoa(from_addr, txn, inspector)
        } else {
            self.scilla_call(from_addr, txn, inspector)
        }?;

        self.mutate_account(from_addr, |from| {
            let refund =
                total_scilla_gas_price(gas_limit - ScillaGas::from(result.gas_used), gas_price);
            from.balance += refund.get();
            from.nonce += 1;
        })?;

        Ok(result)
    }

    #[track_caller]
    fn deduct_from_account(
        &mut self,
        addr: Address,
        amount: ZilAmount,
    ) -> Result<Option<TransactionApplyResult>> {
        let caller = std::panic::Location::caller();
        self.mutate_account(addr, |acc| {
            let Some(balance) = acc.balance.checked_sub(amount.get()) else {
                info!("insufficient balance: {caller}");
                return Some(TransactionApplyResult {
                    success: false,
                    contract_address: None,
                    logs: vec![],
                    gas_used: ScillaGas(0).into(),
                    output: TransactionOutput::Error,
                    accepted: None,
                    errors: [(0, vec![ScillaError::InsufficientBalance])]
                        .into_iter()
                        .collect(),
                    exceptions: vec![],
                });
            };
            acc.balance = balance;
            None
        })
    }

    fn scilla_create(
        &mut self,
        from_addr: Address,
        txn: TxZilliqa,
        current_block: BlockHeader,
        mut inspector: impl ScillaInspector,
    ) -> Result<TransactionApplyResult> {
        if txn.data.is_empty() {
            return Err(anyhow!("contract creation without init data"));
        }

        if let Some(result) = self.deduct_from_account(from_addr, txn.amount)? {
            return Ok(result);
        }

        // The contract address is created with the account's current nonce. The transaction's nonce is one greater
        // than this.
        let contract_address = zil_contract_address(from_addr, txn.nonce - 1);

        let mut init_data: Vec<Value> = serde_json::from_str(&txn.data)?;
        init_data.push(json!({"vname": "_creation_block", "type": "BNum", "value": current_block.number.to_string()}));
        let contract_address_hex = format!("{contract_address:#x}");
        init_data.push(
            json!({"vname": "_this_address", "type": "ByStr20", "value": contract_address_hex}),
        );

        let gas = txn.gas_limit;

        let Some(gas) = gas.checked_sub(SCILLA_INVOKE_CHECKER) else {
            warn!("not enough gas to invoke scilla checker");
            return Ok(TransactionApplyResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
                output: TransactionOutput::Error,
                accepted: Some(false),
                errors: [(0, vec![ScillaError::OutOfGas])].into_iter().collect(),
                exceptions: vec![],
            });
        };

        let check_output = match self.scilla().check_contract(&txn.code, gas, &init_data)? {
            Ok(o) => o,
            Err(e) => {
                warn!(?e, "transaction failed");
                let gas = gas.min(e.gas_remaining);
                return Ok(TransactionApplyResult {
                    success: false,
                    contract_address: Some(contract_address),
                    logs: vec![],
                    gas_used: (txn.gas_limit - gas).into(),
                    output: TransactionOutput::Error,
                    accepted: Some(false),
                    errors: [(0, vec![ScillaError::CreateFailed])].into_iter().collect(),
                    exceptions: e.errors.into_iter().map(Into::into).collect(),
                });
            }
        };

        info!(?check_output);

        let gas = gas.min(check_output.gas_remaining);

        let storage = check_output
            .contract_info
            .fields
            .into_iter()
            .map(|p| {
                (
                    p.name,
                    (
                        if p.depth == 0 {
                            ScillaValue::Bytes(Vec::new())
                        } else {
                            ScillaValue::map()
                        },
                        p.ty,
                    ),
                )
            })
            .collect();

        let account = Account {
            nonce: 0,
            balance: txn.amount.get(),
            contract: Contract::Scilla {
                code: txn.code.clone(),
                init_data: serde_json::to_string(&init_data)?,
                storage,
            },
        };
        self.save_account(contract_address, account)?;

        let Some(gas) = gas.checked_sub(SCILLA_INVOKE_RUNNER) else {
            warn!("not enough gas to invoke scilla runner");
            return Ok(TransactionApplyResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
                output: TransactionOutput::Error,
                accepted: Some(false),
                errors: [(0, vec![ScillaError::OutOfGas])].into_iter().collect(),
                exceptions: vec![],
            });
        };

        let state = self.try_clone()?;
        let (create_output, root_hash) = match self.scilla().create_contract(
            contract_address,
            state,
            &txn.code,
            gas,
            txn.amount,
            &init_data,
        )? {
            Ok(o) => o,
            Err(e) => {
                warn!(?e, "transaction failed");
                let gas = gas.min(e.gas_remaining);
                return Ok(TransactionApplyResult {
                    success: false,
                    contract_address: Some(contract_address),
                    logs: vec![],
                    gas_used: (txn.gas_limit - gas).into(),
                    output: TransactionOutput::Error,
                    accepted: Some(false),
                    errors: [(0, vec![ScillaError::CreateFailed])].into_iter().collect(),
                    exceptions: e.errors.into_iter().map(Into::into).collect(),
                });
            }
        };
        self.set_to_root(root_hash);

        info!(?create_output);

        let gas = gas.min(create_output.gas_remaining);

        inspector.create(from_addr, contract_address, txn.amount.get());

        Ok(TransactionApplyResult {
            success: true,
            contract_address: Some(contract_address),
            logs: vec![],
            gas_used: (txn.gas_limit - gas).into(),
            output: TransactionOutput::Success(vec![]),
            accepted: None,
            errors: BTreeMap::new(),
            exceptions: vec![],
        })
    }

    fn scilla_transfer_to_eoa(
        &mut self,
        from_addr: Address,
        txn: TxZilliqa,
        mut inspector: impl ScillaInspector,
    ) -> Result<TransactionApplyResult> {
        let gas = txn.gas_limit;

        let Some(gas) = gas.checked_sub(SCILLA_TRANSFER) else {
            warn!("not enough gas to make transfer");
            return Ok(TransactionApplyResult {
                success: false,
                contract_address: None,
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
                output: TransactionOutput::Error,
                accepted: Some(false),
                errors: [(0, vec![ScillaError::OutOfGas])].into_iter().collect(),
                exceptions: vec![],
            });
        };

        if let Some(result) = self.deduct_from_account(from_addr, txn.amount)? {
            return Ok(result);
        }

        self.mutate_account(txn.to_addr, |to| {
            to.balance += txn.amount.get();
        })?;

        inspector.transfer(from_addr, txn.to_addr, txn.amount.get());

        Ok(TransactionApplyResult {
            success: true,
            contract_address: None,
            logs: vec![],
            gas_used: (txn.gas_limit - gas).into(),
            output: TransactionOutput::Success(vec![]),
            accepted: None,
            errors: BTreeMap::new(),
            exceptions: vec![],
        })
    }

    fn scilla_call(
        &mut self,
        from_addr: Address,
        txn: TxZilliqa,
        mut inspector: impl ScillaInspector,
    ) -> Result<TransactionApplyResult> {
        // TODO: Interop
        let Contract::Scilla {
            code,
            init_data,
            storage: _,
        } = self.get_account(txn.to_addr)?.contract
        else {
            return Err(anyhow!("Scilla call to a non-Scilla contract"));
        };
        let init_data: Vec<Value> = serde_json::from_str(&init_data)?;

        // TODO: Better parsing here
        let mut message: Value = serde_json::from_str(&txn.data)?;
        message["_amount"] = txn.amount.to_string().into();
        message["_sender"] = format!("{from_addr:#x}").into();
        message["_origin"] = format!("{from_addr:#x}").into();

        let gas = txn.gas_limit;
        let Some(gas) = gas.checked_sub(SCILLA_INVOKE_RUNNER) else {
            warn!("not enough gas to invoke scilla runner");
            return Ok(TransactionApplyResult {
                success: false,
                contract_address: None,
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
                output: TransactionOutput::Error,
                accepted: Some(false),
                errors: [(0, vec![ScillaError::OutOfGas])].into_iter().collect(),
                exceptions: vec![],
            });
        };

        let state = self.try_clone()?;
        let (output, root_hash) = match self.scilla().invoke_contract(
            txn.to_addr,
            state,
            &code,
            txn.gas_limit,
            txn.amount,
            &init_data,
            &message,
        )? {
            Ok(o) => o,
            Err(e) => {
                warn!(?e, "transaction failed");
                let gas = gas.min(e.gas_remaining);
                return Ok(TransactionApplyResult {
                    success: false,
                    contract_address: None,
                    logs: vec![],
                    gas_used: (txn.gas_limit - gas).into(),
                    output: TransactionOutput::Error,
                    accepted: Some(false),
                    errors: [(0, vec![ScillaError::CallFailed])].into_iter().collect(),
                    exceptions: e.errors.into_iter().map(Into::into).collect(),
                });
            }
        };
        self.set_to_root(root_hash);

        info!(?output);

        let gas = gas.min(output.gas_remaining);

        if output.accepted {
            if let Some(result) = self.deduct_from_account(from_addr, txn.amount)? {
                return Ok(result);
            }

            self.mutate_account(txn.to_addr, |to| {
                to.balance += txn.amount.get();
            })?;
        }

        // TODO: Handle `output.messages` for multi-contract calls.

        let logs = output
            .events
            .into_iter()
            .map(|e| {
                Log::scilla(
                    txn.to_addr,
                    e.event_name,
                    e.params
                        .into_iter()
                        .map(|p| ScillaParam {
                            ty: p.ty,
                            value: p.value,
                            name: p.name,
                        })
                        .collect(),
                )
            })
            .collect();

        inspector.call(from_addr, txn.to_addr, txn.amount.get());

        Ok(TransactionApplyResult {
            success: true,
            contract_address: None,
            logs,
            gas_used: (txn.gas_limit - gas).into(),
            output: TransactionOutput::Success(vec![]),
            accepted: Some(output.accepted),
            errors: BTreeMap::new(),
            exceptions: vec![],
        })
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction<I: for<'s> Inspector<&'s State> + ScillaInspector>(
        &mut self,
        txn: VerifiedTransaction,
        chain_id: u64,
        current_block: BlockHeader,
        inspector: I,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash;
        let from_addr = txn.signer;
        info!(?hash, ?txn, "executing txn");

        let txn = txn.tx.into_transaction();
        if let Transaction::Zilliqa(txn) = txn {
            self.apply_transaction_scilla(from_addr, current_block, txn, inspector)
        } else {
            let ResultAndState { result, state } = self.apply_transaction_evm(
                from_addr,
                txn.to_addr(),
                txn.max_fee_per_gas(),
                txn.gas_limit(),
                txn.amount(),
                txn.payload().to_vec(),
                txn.nonce(),
                chain_id,
                current_block,
                inspector,
            )?;

            self.apply_delta_evm(state)?;

            Ok(TransactionApplyResult {
                success: result.is_success(),
                contract_address: if let ExecutionResult::Success {
                    output: Output::Create(_, c),
                    ..
                } = result
                {
                    c
                } else {
                    None
                },
                logs: result
                    .logs()
                    .iter()
                    .map(|l| Log::evm(l.address, l.topics().to_vec(), l.data.data.to_vec()))
                    .collect(),
                gas_used: EvmGas(result.gas_used()),
                output: match result {
                    ExecutionResult::Success { output, .. } => {
                        TransactionOutput::Success(output.into_data().to_vec())
                    }
                    ExecutionResult::Revert { output, .. } => {
                        TransactionOutput::Revert(output.to_vec())
                    }
                    ExecutionResult::Halt { .. } => TransactionOutput::Error,
                },
                accepted: None,
                errors: BTreeMap::new(),
                exceptions: vec![],
            })
        }
    }

    /// Applies a state delta from an EVM execution to the state.
    pub(crate) fn apply_delta_evm(
        &mut self,
        state: revm::primitives::HashMap<Address, revm::primitives::Account>,
    ) -> Result<()> {
        for (address, account) in state {
            let mut storage = self.get_account_trie(address)?;

            for (index, value) in account.changed_storage_slots() {
                let index = B256::new(index.to_be_bytes());
                let value = B256::new(value.present_value().to_be_bytes());
                trace!(?address, ?index, ?value, "update storage");

                storage.insert(&Self::account_storage_key(address, index), value.as_slice())?;
            }

            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.try_into()?,
                contract: Contract::Evm {
                    code: account
                        .info
                        .code
                        .map(|c| c.original_bytes().to_vec())
                        .unwrap_or_default(),
                    storage_root: if storage.iter().count() != 0 {
                        Some(storage.root_hash()?)
                    } else {
                        None
                    },
                },
            };
            trace!(?address, ?account, "update account");
            self.save_account(address, account)?;
        }

        Ok(())
    }

    pub fn get_stakers_at_block(&self, block: &Block) -> Result<Vec<NodePublicKey>> {
        let block_root_hash = block.state_root_hash();

        let state = self.at_root(H256(block_root_hash.0));
        state.get_stakers()
    }

    pub fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        let data = contracts::deposit::GET_STAKERS.encode_input(&[])?;

        let stakers = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
        )?;

        let stakers = contracts::deposit::GET_STAKERS
            .decode_output(&stakers)
            .unwrap()[0]
            .clone()
            .into_array()
            .unwrap();

        Ok(stakers
            .into_iter()
            .map(|k| NodePublicKey::from_bytes(&k.into_bytes().unwrap()).unwrap())
            .collect())
    }

    pub fn get_stake(&self, public_key: NodePublicKey) -> Result<Option<NonZeroU128>> {
        let data =
            contracts::deposit::GET_STAKE.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let stake = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
        )?;

        Ok(NonZeroU128::new(U256::from_be_slice(&stake).to()))
    }

    pub fn get_reward_address(&self, public_key: NodePublicKey) -> Result<Option<Address>> {
        let data = contracts::deposit::GET_REWARD_ADDRESS
            .encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let return_value = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
        )?;

        let addr = contracts::deposit::GET_REWARD_ADDRESS.decode_output(&return_value)?[0]
            .clone()
            .into_address()
            .unwrap();
        let addr = Address::new(addr.0);

        Ok((!addr.is_zero()).then_some(addr))
    }

    pub fn get_peer_id(&self, public_key: NodePublicKey) -> Result<Option<PeerId>> {
        let data =
            contracts::deposit::GET_PEER_ID.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let return_value = self.call_contract(
            Address::zero(),
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
        )?;

        let data = contracts::deposit::GET_PEER_ID.decode_output(&return_value)?[0]
            .clone()
            .into_bytes()
            .unwrap();

        Ok(Some(PeerId::from_bytes(&data)?))
    }

    pub fn get_total_stake(&self) -> Result<u128> {
        let data = contracts::deposit::TOTAL_STAKE.encode_input(&[])?;

        let return_value = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
        )?;

        let amount = contracts::deposit::TOTAL_STAKE.decode_output(&return_value)?[0]
            .clone()
            .into_uint()
            .unwrap();

        Ok(amount.as_u128())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
        gas: Option<EvmGas>,
        gas_price: Option<u128>,
        value: u128,
    ) -> Result<u64> {
        let gas_price = gas_price.unwrap_or(GAS_PRICE);
        let gas = gas.unwrap_or(BLOCK_GAS_LIMIT);

        let ResultAndState { result, .. } = self.apply_transaction_evm(
            from_addr,
            to_addr,
            gas_price,
            gas,
            value,
            data,
            None,
            chain_id,
            current_block,
            inspector::noop(),
        )?;

        match result {
            ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Revert {
                gas_used: _,
                output,
            } => {
                let decoded_revert_msg = extract_revert_msg(&output);
                // See: https://github.com/ethereum/go-ethereum/blob/9b9a1b677d894db951dc4714ea1a46a2e7b74ffc/internal/ethapi/api.go#L1026
                const REVERT_ERROR_CODE: i32 = 3;

                let response = jsonrpsee::types::ErrorObjectOwned::owned(
                    REVERT_ERROR_CODE,
                    decoded_revert_msg,
                    None::<()>,
                );

                Err(response.into())
            }
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("halted due to: {reason:?}")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_contract(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: u128,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<Vec<u8>> {
        let ResultAndState { result, .. } = self.apply_transaction_evm(
            from_addr,
            to_addr,
            GAS_PRICE,
            BLOCK_GAS_LIMIT,
            amount,
            data,
            None,
            chain_id,
            current_block,
            inspector::noop(),
        )?;

        match result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Ok(output.to_vec()),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("halted due to: {reason:?}")),
        }
    }
}

pub enum TransactionOutput {
    Success(Vec<u8>),
    Revert(Vec<u8>),
    Error,
}

impl TransactionOutput {
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            TransactionOutput::Success(v) => v,
            TransactionOutput::Revert(v) => v,
            TransactionOutput::Error => vec![],
        }
    }
}

/// Gets the contract address if a contract creation [TxZilliqa] is sent by `sender` with `nonce`.
pub fn zil_contract_address(sender: Address, nonce: u64) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(sender.into_array());
    hasher.update(nonce.to_be_bytes());
    let hashed = hasher.finalize();
    Address::from_slice(&hashed[12..])
}
