//! Manages execution of transactions on state.

use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap},
    error::Error,
    fmt::{self, Display, Formatter},
    fs, mem,
    num::NonZeroU128,
    path::Path,
    sync::{Arc, MutexGuard},
};

use alloy::primitives::{hex, Address, U256};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use eth_trie::{EthTrie, Trie};
use ethabi::Token;
use libp2p::PeerId;
use revm::{
    inspector_handle_register,
    primitives::{
        AccountInfo, BlockEnv, Bytecode, Env, ExecutionResult, HaltReason, HandlerCfg, Output,
        ResultAndState, SpecId, TxEnv, B256, KECCAK_EMPTY,
    },
    Database, DatabaseRef, Evm, Inspector,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, info, trace, warn};

use crate::{
    contracts,
    crypto::{Hash, NodePublicKey, NodePublicKeyRaw},
    db::TrieStorage,
    eth_helpers::extract_revert_msg,
    inspector::{self, ScillaInspector},
    message::{Block, BlockHeader},
    precompiles::{get_custom_precompiles, scilla_call_handle_register},
    scilla::{self, split_storage_key, storage_key, Scilla},
    state::{
        contract_addr, Account, Code, ContractInit, ContractInitEntry, ExternalLibrary, State,
    },
    time::SystemTime,
    transaction::{
        total_scilla_gas_price, EvmGas, EvmLog, Log, ScillaGas, ScillaLog, ScillaParam,
        Transaction, TxZilliqa, VerifiedTransaction, ZilAmount,
    },
};

type ScillaResultAndState = (ScillaResult, HashMap<Address, PendingAccount>);

/// Data returned after applying a [Transaction] to [State].

#[derive(Clone)]
pub enum TransactionApplyResult {
    Evm(ResultAndState, Box<Env>),
    Scilla(ScillaResultAndState),
}

impl TransactionApplyResult {
    pub fn output(&self) -> Option<&[u8]> {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => {
                result.output().map(|b| b.as_ref())
            }
            TransactionApplyResult::Scilla(_) => None,
        }
    }

    pub fn success(&self) -> bool {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => result.is_success(),
            TransactionApplyResult::Scilla((ScillaResult { success, .. }, _)) => *success,
        }
    }

    pub fn contract_address(&self) -> Option<Address> {
        match self {
            TransactionApplyResult::Evm(
                ResultAndState {
                    result: ExecutionResult::Success { output, .. },
                    ..
                },
                ..,
            ) => output.address().copied(),
            TransactionApplyResult::Evm(_, _) => None,
            TransactionApplyResult::Scilla((
                ScillaResult {
                    contract_address, ..
                },
                _,
            )) => *contract_address,
        }
    }

    pub fn gas_used(&self) -> EvmGas {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => {
                EvmGas(result.gas_used())
            }
            TransactionApplyResult::Scilla((ScillaResult { gas_used, .. }, _)) => *gas_used,
        }
    }

    pub fn accepted(&self) -> Option<bool> {
        match self {
            TransactionApplyResult::Evm(_, _) => None,
            TransactionApplyResult::Scilla((ScillaResult { accepted, .. }, _)) => *accepted,
        }
    }

    pub fn exceptions(&self) -> &[ScillaException] {
        match self {
            TransactionApplyResult::Evm(_, _) => &[],
            TransactionApplyResult::Scilla((ScillaResult { exceptions, .. }, _)) => exceptions,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        Vec<Log>,
        Vec<ScillaTransition>,
        BTreeMap<u64, Vec<ScillaError>>,
        Vec<ScillaException>,
    ) {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => (
                result
                    .into_logs()
                    .into_iter()
                    .map(|l| {
                        let (topics, data) = l.data.split();
                        Log::Evm(EvmLog {
                            address: l.address,
                            topics,
                            data: data.to_vec(),
                        })
                    })
                    .collect(),
                Vec::new(),
                BTreeMap::new(),
                Vec::new(),
            ),
            TransactionApplyResult::Scilla((
                ScillaResult {
                    logs,
                    transitions,
                    errors,
                    exceptions,
                    ..
                },
                _,
            )) => (
                logs.into_iter().map(Log::Scilla).collect(),
                transitions,
                errors,
                exceptions,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScillaTransition {
    /// The address of the Scilla contract which initiated the transition.
    pub from: Address,
    /// The recipient of the transition.
    pub to: Address,
    /// The call depth of the transition.
    pub depth: u64,
    /// The value passed with the transition.
    pub amount: ZilAmount,
    /// The tag of the transition. If the recipient is a Scilla contract, this is the method that will be called.
    pub tag: String,
    /// Any parameters passed with the transition.
    pub params: String,
}

impl ScillaTransition {
    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.from.0.as_slice())
            .with(self.to.0.as_slice())
            .with(self.depth.to_be_bytes())
            .with(self.amount.to_be_bytes())
            .with(self.tag.as_bytes())
            .with(self.params.as_bytes())
            .finalize()
    }
}

#[derive(Clone)]
pub struct ScillaResult {
    /// Whether the transaction succeeded and the resulting state changes were persisted.
    pub success: bool,
    /// If the transaction was a contract creation, the address of the resulting contract.
    pub contract_address: Option<Address>,
    /// The logs emitted by the transaction execution.
    pub logs: Vec<ScillaLog>,
    /// The gas paid by the transaction
    pub gas_used: EvmGas,
    /// Scilla transitions executed by the transaction execution.
    pub transitions: Vec<ScillaTransition>,
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

impl ScillaException {
    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.line.to_be_bytes())
            .with(self.message.as_bytes())
            .finalize()
    }
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

impl Database for PendingState {
    type Error = DatabaseError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        (&self.pre_state).basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        (&self.pre_state).code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        (&self.pre_state).storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        (&self.pre_state).block_hash_ref(number)
    }
}

impl DatabaseRef for PendingState {
    type Error = DatabaseError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        (&self.pre_state).basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        (&self.pre_state).code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        (&self.pre_state).storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        (&self.pre_state).block_hash_ref(number)
    }
}

impl Database for &State {
    type Error = DatabaseError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

impl DatabaseRef for &State {
    type Error = DatabaseError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if !self.has_account(address)? {
            return Ok(None);
        }

        let account = self.get_account(address)?;
        let code = Bytecode::new_raw(account.code.evm_code().unwrap_or_default().into());
        let account_info = AccountInfo {
            balance: U256::from(account.balance),
            nonce: account.nonce,
            code_hash: code.hash_slow(),
            code: Some(code),
        };

        Ok(Some(account_info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let index = B256::new(index.to_be_bytes());

        let result = self.get_account_storage(address, index)?;

        Ok(U256::from_be_bytes(result.0))
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        // TODO
        Ok(B256::ZERO)
    }
}

// As per EIP-150
pub const MAX_EVM_GAS_LIMIT: EvmGas = EvmGas(5_500_000);

pub const SCILLA_TRANSFER: ScillaGas = ScillaGas(50);
pub const SCILLA_INVOKE_CHECKER: ScillaGas = ScillaGas(100);
pub const SCILLA_INVOKE_RUNNER: ScillaGas = ScillaGas(300);

const SPEC_ID: SpecId = SpecId::SHANGHAI;

pub enum BaseFeeCheck {
    /// Transaction gas price will be validated to be at least the block gas price.
    Validate,
    /// Transaction gas price will not be validated.
    Ignore,
}

impl State {
    /// Used primarily during genesis to set up contracts for chain functionality.
    /// If override_address address is set, forces contract deployment to that addess.
    pub(crate) fn force_deploy_contract_evm(
        &mut self,
        creation_bytecode: Vec<u8>,
        override_address: Option<Address>,
    ) -> Result<Address> {
        let (ResultAndState { result, mut state }, ..) = self.apply_transaction_evm(
            Address::ZERO,
            None,
            0,
            self.block_gas_limit,
            0,
            creation_bytecode,
            None,
            BlockHeader::genesis(Hash::ZERO),
            inspector::noop(),
            BaseFeeCheck::Ignore,
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

                self.apply_delta_evm(&state)?;
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
    pub fn apply_transaction_evm<I: Inspector<PendingState> + ScillaInspector>(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u128,
        gas_limit: EvmGas,
        amount: u128,
        payload: Vec<u8>,
        nonce: Option<u64>,
        current_block: BlockHeader,
        inspector: I,
        base_fee_check: BaseFeeCheck,
    ) -> Result<(ResultAndState, HashMap<Address, PendingAccount>, Box<Env>)> {
        let mut padded_view_number = [0u8; 32];
        padded_view_number[24..].copy_from_slice(&current_block.view.to_be_bytes());

        let pending_state = PendingState::new(self.clone());
        let mut evm = Evm::builder()
            .with_db(pending_state)
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
                gas_limit: U256::from(self.block_gas_limit.0),
                basefee: U256::from(self.gas_price),
                difficulty: U256::from(1),
                prevrandao: Some(Hash::builder().with(padded_view_number).finalize().into()),
                blob_excess_gas_and_price: None,
            })
            .with_external_context(inspector)
            .with_handler_cfg(HandlerCfg { spec_id: SPEC_ID })
            .append_handler_register(scilla_call_handle_register)
            .append_handler_register(inspector_handle_register)
            .modify_cfg_env(|c| {
                c.chain_id = self.chain_id.eth;
                c.disable_base_fee = match base_fee_check {
                    BaseFeeCheck::Validate => false,
                    BaseFeeCheck::Ignore => true,
                };
            })
            .with_tx_env(TxEnv {
                caller: from_addr.0.into(),
                gas_limit: gas_limit.0,
                gas_price: U256::from(gas_price),
                transact_to: to_addr.into(),
                value: U256::from(amount),
                data: payload.clone().into(),
                nonce,
                chain_id: Some(self.chain_id.eth),
                access_list: vec![],
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: None,
                authorization_list: None,
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
        let (mut state, cfg) = evm.into_db_and_env_with_handler_cfg();
        Ok((e, state.finalize(), cfg.env))
    }

    fn apply_transaction_scilla(
        &mut self,
        from_addr: Address,
        txn: TxZilliqa,
        current_block: BlockHeader,
        inspector: impl ScillaInspector,
    ) -> Result<ScillaResultAndState> {
        let mut state = PendingState::new(self.try_clone()?);

        let deposit = total_scilla_gas_price(txn.gas_limit, txn.gas_price);
        if let Some(result) = state.deduct_from_account(from_addr, deposit)? {
            return Ok((result, state.finalize()));
        }

        let gas_limit = txn.gas_limit;
        let gas_price = txn.gas_price;

        let (result, mut state) = if txn.to_addr.is_zero() {
            scilla_create(
                state,
                self.scilla(),
                from_addr,
                txn,
                current_block,
                inspector,
                &self.scilla_ext_libs_cache_folder.on_host,
            )
        } else {
            scilla_call(
                state,
                self.scilla(),
                from_addr,
                from_addr,
                txn.gas_limit,
                txn.to_addr,
                txn.amount,
                txn.data,
                inspector,
            )
        }?;

        let from = state.load_account(from_addr)?;
        let refund =
            total_scilla_gas_price(gas_limit - ScillaGas::from(result.gas_used), gas_price);
        from.account.balance += refund.get();
        from.account.nonce += 1;

        Ok((result, state.finalize()))
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction<I: Inspector<PendingState> + ScillaInspector>(
        &mut self,
        txn: VerifiedTransaction,
        current_block: BlockHeader,
        inspector: I,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash;
        let from_addr = txn.signer;
        info!(?hash, ?txn, "executing txn");

        let blessed = BLESSED_TRANSACTIONS.contains(&hash);

        let txn = txn.tx.into_transaction();
        if let Transaction::Zilliqa(txn) = txn {
            let (result, state) =
                self.apply_transaction_scilla(from_addr, txn, current_block, inspector)?;

            self.apply_delta_scilla(&state)?;

            Ok(TransactionApplyResult::Scilla((result, state)))
        } else {
            let (ResultAndState { result, state }, scilla_state, env) = self
                .apply_transaction_evm(
                    from_addr,
                    txn.to_addr(),
                    txn.max_fee_per_gas(),
                    txn.gas_limit(),
                    txn.amount(),
                    txn.payload().to_vec(),
                    txn.nonce(),
                    current_block,
                    inspector,
                    if blessed {
                        BaseFeeCheck::Ignore
                    } else {
                        BaseFeeCheck::Validate
                    },
                )?;

            self.apply_delta_evm(&state)?;
            self.apply_delta_scilla(&scilla_state)?;

            Ok(TransactionApplyResult::Evm(
                ResultAndState { result, state },
                env,
            ))
        }
    }

    /// Applies a state delta from a Scilla execution to the state.
    fn apply_delta_scilla(&mut self, state: &HashMap<Address, PendingAccount>) -> Result<()> {
        for (&address, account) in state {
            let mut storage = self.get_account_trie(address)?;

            /// Recursively called internal function which assigns `value` at the correct key to `storage`.
            fn handle(
                storage: &mut EthTrie<TrieStorage>,
                var: &str,
                value: &StorageValue,
                indices: &mut Vec<Vec<u8>>,
            ) -> Result<()> {
                match value {
                    StorageValue::Map { map, complete } => {
                        // If this is a complete view of the map, delete any existing values first.
                        if *complete {
                            storage.remove_by_prefix(&storage_key(var, indices))?;
                        }

                        // We will iterate over each key-value pair in this map and make a recursive call to this
                        // function with the given value. Before each call, we need to make sure we update `inidices`
                        // to include the key. To avoid changing the length of the `Vec` in each iteration, we first
                        // add a dummy index (`vec![]`) and update it before each call.
                        indices.push(vec![]);
                        for (k, v) in map {
                            indices.last_mut().unwrap().clone_from(k);
                            handle(storage, var, v, indices)?;
                        }
                    }
                    StorageValue::Value(Some(value)) => {
                        let key = storage_key(var, indices);
                        storage.insert(&key, value)?;
                    }
                    StorageValue::Value(None) => {
                        let key = storage_key(var, indices);
                        // A deletion may occur at any depth of the map. Therefore we remove all keys with the relevent
                        // prefix.
                        storage.remove_by_prefix(&key)?;
                    }
                }
                Ok(())
            }

            for (var, value) in &account.storage {
                handle(&mut storage, var, value, &mut vec![])?;
            }

            let account = Account {
                nonce: account.account.nonce,
                balance: account.account.balance,
                code: account.account.code.clone(),
                storage_root: storage.root_hash()?,
            };

            self.save_account(address, account)?;
        }

        Ok(())
    }

    /// Applies a state delta from an EVM execution to the state.
    pub fn apply_delta_evm(
        &mut self,
        state: &HashMap<Address, revm::primitives::Account>,
    ) -> Result<()> {
        for (&address, account) in state {
            let mut storage = self.get_account_trie(address)?;

            for (index, value) in account.changed_storage_slots() {
                let index = B256::new(index.to_be_bytes());
                let value = B256::new(value.present_value().to_be_bytes());
                trace!(?address, ?index, ?value, "update storage");

                storage.insert(
                    &Self::account_storage_key(address, index).0,
                    value.as_slice(),
                )?;
            }

            // `account.info.code` might be `None`, even though we always return `Some` for the account code in our
            // [DatabaseRef] implementation. However, this is only the case for empty code, so we handle this case
            // separately.
            let code = if account.info.code_hash == KECCAK_EMPTY {
                vec![]
            } else {
                account
                    .info
                    .code
                    .as_ref()
                    .expect("code_by_hash is not used")
                    .original_bytes()
                    .to_vec()
            };

            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.try_into()?,
                code: Code::Evm(code),
                storage_root: storage.root_hash()?,
            };
            trace!(?address, ?account, "update account");
            self.save_account(address, account)?;
        }

        Ok(())
    }

    pub fn leader(&self, view: u64) -> Result<NodePublicKey> {
        self.leader_raw(view).and_then(|leader| leader.try_into())
    }

    pub fn leader_raw(&self, view: u64) -> Result<NodePublicKeyRaw> {
        let data = contracts::deposit::LEADER_AT_VIEW.encode_input(&[Token::Uint(view.into())])?;

        let leader = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            BlockHeader::default(),
        )?;

        Ok(NodePublicKeyRaw::from_bytes(
            &contracts::deposit::LEADER_AT_VIEW
                .decode_output(&leader)
                .unwrap()[0]
                .clone()
                .into_bytes()
                .unwrap(),
        ))
    }

    pub fn get_stakers_at_block(&self, block: &Block) -> Result<Vec<NodePublicKey>> {
        self.get_stakers_at_block_raw(block)
            .and_then(|result| result.into_iter().map(|k| k.try_into()).collect())
    }

    pub fn get_stakers_at_block_raw(&self, block: &Block) -> Result<Vec<NodePublicKeyRaw>> {
        let block_root_hash = block.state_root_hash();

        let state = self.at_root(block_root_hash.into());
        state.get_stakers_raw()
    }

    pub fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        self.get_stakers_raw()
            .and_then(|result| result.into_iter().map(|k| k.try_into()).collect())
    }

    pub fn get_stakers_raw(&self) -> Result<Vec<NodePublicKeyRaw>> {
        let data = contracts::deposit::GET_STAKERS.encode_input(&[])?;

        let stakers = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The current block is not accessed when the native balance is read, so we just pass in some
            // dummy values.
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
            .map(|k| NodePublicKeyRaw::from_bytes(&k.into_bytes().unwrap()))
            .collect())
    }

    pub fn get_stake(&self, public_key: NodePublicKey) -> Result<Option<NonZeroU128>> {
        self.get_stake_raw(public_key.into())
    }

    pub fn get_stake_raw(&self, public_key: NodePublicKeyRaw) -> Result<Option<NonZeroU128>> {
        let data =
            contracts::deposit::GET_STAKE.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let stake = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The current block is not accessed when the native balance is read, so we just pass in some
            // dummy values.
            BlockHeader::default(),
        )?;

        let stake = NonZeroU128::new(U256::from_be_slice(&stake).to());

        Ok(stake)
    }

    pub fn get_reward_address(&self, public_key: NodePublicKey) -> Result<Option<Address>> {
        self.get_reward_address_raw(public_key.into())
    }

    pub fn get_reward_address_raw(&self, public_key: NodePublicKeyRaw) -> Result<Option<Address>> {
        let data = contracts::deposit::GET_REWARD_ADDRESS
            .encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let return_value = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The current block is not accessed when the native balance is read, so we just pass in some
            // dummy values.
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
        self.get_peer_id_raw(public_key.into())
    }

    pub fn get_peer_id_raw(&self, public_key: NodePublicKeyRaw) -> Result<Option<PeerId>> {
        let data =
            contracts::deposit::GET_PEER_ID.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let return_value = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The current block is not accessed when the native balance is read, so we just pass in some
            // dummy values.
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
            // The current block is not accessed when the native balance is read, so we just pass in some
            // dummy values.
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
        current_block: BlockHeader,
        gas: Option<EvmGas>,
        gas_price: Option<u128>,
        value: u128,
    ) -> Result<u64> {
        let gas_price = gas_price.unwrap_or(self.gas_price);

        let mut max = gas.unwrap_or(MAX_EVM_GAS_LIMIT).0;
        let upper_bound = max;

        // Check if estimation succeeds with the highest possible gas
        // We use the result as lower bound
        let mut min = self.estimate_gas_inner(
            from_addr,
            to_addr,
            data.clone(),
            current_block,
            EvmGas(upper_bound),
            gas_price,
            value,
        )?;

        // Execute the while loop iff (max - min)/max < MINIMUM_PERCENT_RATIO [%]
        const MINIMUM_PERCENT_RATIO: u64 = 3;

        // result should be somewhere in (min, max]
        while min < max {
            let break_cond = (max - min) <= (max * MINIMUM_PERCENT_RATIO) / 100;
            if break_cond {
                break;
            }
            let mid = (min + max) / 2;

            let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
                from_addr,
                to_addr,
                gas_price,
                EvmGas(mid),
                value,
                data.clone(),
                None,
                current_block,
                inspector::noop(),
                BaseFeeCheck::Validate,
            )?;

            match result {
                ExecutionResult::Success { .. } => max = mid,
                ExecutionResult::Revert { .. } => min = mid + 1,
                ExecutionResult::Halt { reason, .. } => match reason {
                    HaltReason::OutOfGas(_) | HaltReason::InvalidFEOpcode => min = mid + 1,
                    _ => return Err(anyhow!("halted due to: {reason:?}")),
                },
            }
        }
        debug!("Estimated gas: {}", max);
        Ok(max)
    }
    #[allow(clippy::too_many_arguments)]
    fn estimate_gas_inner(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        current_block: BlockHeader,
        gas: EvmGas,
        gas_price: u128,
        value: u128,
    ) -> Result<u64> {
        let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            gas_price,
            gas,
            value,
            data.clone(),
            None,
            current_block,
            inspector::noop(),
            BaseFeeCheck::Validate,
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
                    Some(output),
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
        current_block: BlockHeader,
    ) -> Result<Vec<u8>> {
        let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            0,
            self.block_gas_limit,
            amount,
            data,
            None,
            current_block,
            inspector::noop(),
            BaseFeeCheck::Ignore,
        )?;

        match result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Ok(output.to_vec()),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("halted due to: {reason:?}")),
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

/// The account state during the execution of a Scilla transaction. Changes to the original state are kept in memory.
#[derive(Debug)]
pub struct PendingState {
    pub pre_state: State,
    pub new_state: HashMap<Address, PendingAccount>,
}

/// Private helper function for `PendingState::load_account`. The only difference is that the fields of `PendingState`
/// are passed explicitly. This means the borrow-checker can see the reference we return only borrows from the
/// `new_state` field and thus we can later use `pre_state` without an error.
fn load_account<'a>(
    pre_state: &State,
    new_state: &'a mut HashMap<Address, PendingAccount>,
    address: Address,
) -> Result<&'a mut PendingAccount> {
    match new_state.entry(address) {
        Entry::Occupied(entry) => Ok(entry.into_mut()),
        Entry::Vacant(vac) => {
            let account = pre_state.get_account(address)?;
            Ok(vac.insert(account.into()))
        }
    }
}

impl PendingState {
    pub fn new(state: State) -> Self {
        PendingState {
            pre_state: state,
            new_state: HashMap::new(),
        }
    }

    pub fn zil_chain_id(&self) -> u64 {
        self.pre_state.chain_id.zil()
    }

    pub fn get_block_by_number(&self, block_number: u64) -> Result<Option<Block>> {
        self.pre_state.block_store.get_block_by_number(block_number)
    }

    pub fn get_highest_block_number(&self) -> Result<Option<u64>> {
        self.pre_state.block_store.get_highest_block_number()
    }

    pub fn load_account(&mut self, address: Address) -> Result<&mut PendingAccount> {
        load_account(&self.pre_state, &mut self.new_state, address)
    }

    pub fn load_var_info(&mut self, address: Address, variable: &str) -> Result<(&str, u8)> {
        let account = self.load_account(address)?;
        let Code::Scilla { types, .. } = &account.account.code else {
            return Err(anyhow!("not a scilla contract"));
        };
        let (ty, depth) = types
            .get(variable)
            .ok_or_else(|| anyhow!("missing type for variable: {variable}"))?;
        Ok((ty, *depth))
    }

    /// Set the value of a given variable at the given indices. This can be used for setting map values, unlike
    /// `load_storage`.
    pub fn set_storage(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
        value: StorageValue,
    ) -> Result<()> {
        let account = load_account(&self.pre_state, &mut self.new_state, address)?;

        let mut current = account
            .storage
            .entry(var_name.to_owned())
            .or_insert_with(StorageValue::incomplete_map);
        for key in indices {
            let current_map = match current {
                StorageValue::Map { map, .. } => map,
                StorageValue::Value(Some(_)) => {
                    return Err(anyhow!("expected a map"));
                }
                StorageValue::Value(None) => {
                    // This branch is unreachable because `update_state_value` in `ActiveCall` asserts that a deletion
                    // can only occur at the same depth as a variable.
                    unreachable!("deletes of whole maps are unsupported")
                }
            };
            let child = current_map
                .entry(key.clone())
                .or_insert_with(StorageValue::incomplete_map);
            current = child;
        }

        *current = value;

        Ok(())
    }

    pub fn load_storage(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
    ) -> Result<&mut Option<Bytes>> {
        let account = load_account(&self.pre_state, &mut self.new_state, address)?;

        fn get_cached<'a>(
            storage: &'a mut BTreeMap<String, StorageValue>,
            var_name: &str,
            indices: &[Vec<u8>],
        ) -> Result<(&'a mut StorageValue, bool)> {
            let mut cached = true;
            let mut current = storage.entry(var_name.to_owned()).or_insert_with(|| {
                cached = false;
                StorageValue::incomplete_map()
            });
            for key in indices {
                let current_map = match current {
                    StorageValue::Map { map, .. } => map,
                    StorageValue::Value(Some(_)) => {
                        return Err(anyhow!("expected a map"));
                    }
                    StorageValue::Value(None) => {
                        // This branch is unreachable because `update_state_value` in `ActiveCall` asserts that a deletion
                        // can only occur at the same depth as a variable.
                        unreachable!("deletes of whole maps are unsupported")
                    }
                };
                let child = current_map.entry(key.clone()).or_insert_with(|| {
                    cached = false;
                    StorageValue::incomplete_map()
                });
                current = child;
            }
            Ok((current, cached))
        }

        let (value, cached) = get_cached(&mut account.storage, var_name, indices)?;

        if !cached {
            let value_from_disk = self
                .pre_state
                .get_account_trie(address)?
                .get(&storage_key(var_name, indices))?
                .map(Vec::<u8>::from);

            *value = StorageValue::Value(value_from_disk.map(|b| b.into()));
        }

        match value {
            StorageValue::Map { .. } => Err(anyhow!("expected bytes")),
            StorageValue::Value(value) => Ok(value),
        }
    }

    pub fn load_storage_by_prefix(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
    ) -> Result<BTreeMap<Vec<u8>, StorageValue>> {
        let account = load_account(&self.pre_state, &mut self.new_state, address)?;

        // Even if we have something cached for this prefix, we don't know if it is a full representation of the map.
        // It might have been the case that only a few subfields were cached. Therefore, we need to retrieve the full
        // map from disk and apply any cached (and potentially updated) values. In future, we should use the 'complete'
        // flag on maps to avoid needing to read from disk unconditionally.

        let values_from_disk: Vec<_> = self
            .pre_state
            .get_account_trie(address)?
            .iter_by_prefix(&storage_key(var_name, indices))?
            .collect();

        let mut map = StorageValue::complete_map();
        let cached = account.storage.get(var_name);

        // Un-flatten the values from disk into their true representation.
        for (k, v) in values_from_disk {
            let (disk_var_name, disk_indices) = split_storage_key(&k)?;
            assert_eq!(var_name, disk_var_name);
            assert!(disk_indices.starts_with(indices));

            let mut current_value = &mut map;
            let mut current_cached = cached;

            for index in disk_indices {
                if let Some(c) = current_cached {
                    match c {
                        StorageValue::Map { map, .. } => {
                            current_cached = map.get(&index);
                        }
                        // This branch can be hit in two cases:
                        // * Firstly, we expect the final index to point to a value in the cache, rather than a map.
                        // * Secondly, if a portion of the map has been deleted, then the cache can contain a `None`
                        // value at a greater height than the depth of the map.
                        StorageValue::Value(_) => {}
                    }
                }

                let map = match current_value {
                    StorageValue::Map { map, .. } => map,
                    StorageValue::Value(_) => {
                        return Err(anyhow!("expected map"));
                    }
                };
                // Note that we insert 'complete' maps here, because we know we are going to add *ALL* values from
                // with this prefix.
                current_value = map.entry(index).or_insert_with(StorageValue::complete_map);
            }

            *current_value = if let Some(cached) = current_cached {
                cached.clone()
            } else {
                StorageValue::Value(Some(v.into()))
            };
        }

        let map = match map {
            StorageValue::Map { map, .. } => map,
            StorageValue::Value(_) => {
                return Err(anyhow!("expected map"));
            }
        };

        Ok(map)
    }

    #[track_caller]
    pub fn deduct_from_account(
        &mut self,
        address: Address,
        amount: ZilAmount,
    ) -> Result<Option<ScillaResult>> {
        let caller = std::panic::Location::caller();
        let account = self.load_account(address)?;
        let Some(balance) = account.account.balance.checked_sub(amount.get()) else {
            info!("insufficient balance: {caller}");
            return Ok(Some(ScillaResult {
                success: false,
                contract_address: None,
                logs: vec![],
                gas_used: ScillaGas(0).into(),
                transitions: vec![],
                accepted: None,
                errors: [(0, vec![ScillaError::InsufficientBalance])]
                    .into_iter()
                    .collect(),
                exceptions: vec![],
            }));
        };
        account.account.balance = balance;
        Ok(None)
    }

    /// Return the changed state and resets the [PendingState] to its initial state in [PendingState::new].
    pub fn finalize(&mut self) -> HashMap<Address, PendingAccount> {
        mem::take(&mut self.new_state)
    }
}

#[derive(Clone, Debug)]
pub struct PendingAccount {
    pub account: Account,
    /// Cached values of updated or deleted storage. Note that deletions can happen at any level of a map.
    pub storage: BTreeMap<String, StorageValue>,
}

#[derive(Debug, Clone)]
pub enum StorageValue {
    Map {
        map: BTreeMap<Vec<u8>, StorageValue>,
        complete: bool,
    },
    /// A value can either be `Some(bytes)` to represent an updated value or `None` to represent a deleted value.
    Value(Option<Bytes>),
}

impl StorageValue {
    pub fn incomplete_map() -> StorageValue {
        StorageValue::Map {
            map: BTreeMap::new(),
            complete: false,
        }
    }

    pub fn complete_map() -> StorageValue {
        StorageValue::Map {
            map: BTreeMap::new(),
            complete: true,
        }
    }
}

impl From<Account> for PendingAccount {
    fn from(account: Account) -> PendingAccount {
        PendingAccount {
            account,
            storage: BTreeMap::new(),
        }
    }
}

fn cache_external_libraries(
    state: &State,
    ext_libs_cache_dir: &str,
    ext_libraries: &[ExternalLibrary],
) -> Result<()> {
    let ext_libs_path = Path::new(ext_libs_cache_dir);

    for lib in ext_libraries {
        let account = state.get_account(lib.address)?;
        match &account.code {
            Code::Evm(_) => {
                return Err(anyhow!(
                    "impossible to load an EVM contract as a scilla library."
                ))
            }
            Code::Scilla {
                code, init_data, ..
            } => {
                if !init_data.is_library {
                    return Err(anyhow!(
                        "impossible to load a non-library contract as a scilla library"
                    ));
                }

                let file_path = ext_libs_path.join(&lib.name);
                fs::write(&file_path, code).context(format!(
                    "failed to write the contract code to {:?}",
                    file_path
                ))?;
            }
        }
    }
    Ok(())
}

fn scilla_create(
    mut state: PendingState,
    scilla: MutexGuard<'_, Scilla>,
    from_addr: Address,
    txn: TxZilliqa,
    current_block: BlockHeader,
    mut inspector: impl ScillaInspector,
    ext_libs_cache_dir: &str,
) -> Result<(ScillaResult, PendingState)> {
    if txn.data.is_empty() {
        return Err(anyhow!("contract creation without init data"));
    }

    if let Some(result) = state.deduct_from_account(from_addr, txn.amount)? {
        return Ok((result, state));
    }

    // The contract address is created with the account's current nonce. The transaction's nonce is one greater
    // than this.
    let contract_address = zil_contract_address(from_addr, txn.nonce - 1);

    let mut init_data: Vec<ContractInitEntry> = serde_json::from_str(&txn.data)?;
    init_data.push(ContractInitEntry {
        vname: "_creation_block".to_string(),
        value: Value::String(current_block.number.to_string()),
        r#type: "BNum".to_string(),
    });
    let contract_address_hex = format!("{contract_address:#x}");
    init_data.push(ContractInitEntry {
        vname: "_this_address".to_string(),
        value: Value::String(contract_address_hex),
        r#type: "ByStr20".to_string(),
    });

    let gas = txn.gas_limit;

    let Some(gas) = gas.checked_sub(SCILLA_INVOKE_CHECKER) else {
        warn!("not enough gas to invoke scilla checker");
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
                transitions: vec![],
                accepted: Some(false),
                errors: [(0, vec![ScillaError::OutOfGas])].into_iter().collect(),
                exceptions: vec![],
            },
            state,
        ));
    };

    let init_data = ContractInit::new(&init_data)?;
    println!("{init_data:#?}");

    cache_external_libraries(
        &state.pre_state,
        &ext_libs_cache_dir,
        &init_data.external_libraries,
    )?;
    let check_output = match scilla.check_contract(&txn.code, gas, &init_data)? {
        Ok(o) => o,
        Err(e) => {
            warn!(?e, "transaction failed");
            return Ok((
                ScillaResult {
                    success: false,
                    contract_address: Some(contract_address),
                    logs: vec![],
                    gas_used: (txn.gas_limit - gas).into(),
                    transitions: vec![],
                    accepted: Some(false),
                    errors: [(0, vec![ScillaError::CreateFailed])].into_iter().collect(),
                    exceptions: e.errors.into_iter().map(Into::into).collect(),
                },
                state,
            ));
        }
    };

    info!(?check_output);

    let gas = gas.min(check_output.gas_remaining);

    let contract_info = check_output.contract_info.unwrap_or_default();
    let types = contract_info
        .fields
        .into_iter()
        .map(|p| (p.name, (p.ty, p.depth as u8)))
        .collect();

    let transitions = contract_info.transitions;

    let account = state.load_account(contract_address)?;
    account.account.balance = txn.amount.get();
    account.account.code = Code::Scilla {
        code: txn.code.clone(),
        init_data: init_data.clone(), // FIXME: Remove this clone
        types,
        transitions,
    };

    let Some(gas) = gas.checked_sub(SCILLA_INVOKE_RUNNER) else {
        warn!("not enough gas to invoke scilla runner");
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
                transitions: vec![],
                accepted: Some(false),
                errors: [(0, vec![ScillaError::OutOfGas])].into_iter().collect(),
                exceptions: vec![],
            },
            state,
        ));
    };

    let (create_output, state) = scilla.create_contract(
        state,
        contract_address,
        &txn.code,
        gas,
        txn.amount,
        &init_data,
    )?;
    let create_output = match create_output {
        Ok(o) => o,
        Err(e) => {
            warn!(?e, "transaction failed");
            let gas = gas.min(e.gas_remaining);
            return Ok((
                ScillaResult {
                    success: false,
                    contract_address: Some(contract_address),
                    logs: vec![],
                    gas_used: (txn.gas_limit - gas).into(),
                    transitions: vec![],
                    accepted: Some(false),
                    errors: [(0, vec![ScillaError::CreateFailed])].into_iter().collect(),
                    exceptions: e.errors.into_iter().map(Into::into).collect(),
                },
                state,
            ));
        }
    };

    info!(?create_output);

    let gas = gas.min(create_output.gas_remaining);

    inspector.create(from_addr, contract_address, txn.amount.get());

    Ok((
        ScillaResult {
            success: true,
            contract_address: Some(contract_address),
            logs: vec![],
            gas_used: (txn.gas_limit - gas).into(),
            transitions: vec![],
            accepted: None,
            errors: BTreeMap::new(),
            exceptions: vec![],
        },
        state,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn scilla_call(
    state: PendingState,
    scilla: MutexGuard<'_, Scilla>,
    from_addr: Address,
    sender: Address,
    gas_limit: ScillaGas,
    to_addr: Address,
    amount: ZilAmount,
    data: String,
    mut inspector: impl ScillaInspector,
) -> Result<(ScillaResult, PendingState)> {
    let mut gas = gas_limit;

    let message = if !data.is_empty() {
        let mut m: Value = serde_json::from_str(&data)?;
        m["_amount"] = amount.to_string().into();
        m["_sender"] = format!("{sender:#x}").into();
        m["_origin"] = format!("{from_addr:#x}").into();
        Some(m)
    } else {
        None
    };

    let mut call_stack = vec![(0, sender, to_addr, amount, message)];
    let mut logs = vec![];
    let mut transitions = vec![];
    let mut root_contract_accepted = false;

    let mut state = Some(state);

    while let Some((depth, sender, to_addr, amount, message)) = call_stack.pop() {
        let mut current_state = state.take().expect("missing state");

        let contract = current_state.load_account(to_addr)?;
        let code_and_data = match &contract.account.code {
            // EOAs are currently represented by [Code::Evm] with no code.
            Code::Evm(code) if code.is_empty() => None,
            Code::Scilla {
                code, init_data, ..
            } => Some((code, init_data)),
            // Calls to EVM contracts should fail.
            Code::Evm(_) => {
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used: (gas_limit - gas).into(),
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(depth, vec![ScillaError::CallFailed])]
                            .into_iter()
                            .collect(),
                        exceptions: vec![ScillaException {
                            line: 0,
                            message: "Scilla call to EVM contract".to_owned(),
                        }],
                    },
                    current_state,
                ));
            }
        };

        if let Some((code, init_data)) = code_and_data {
            // The `to_addr` is a Scilla contract, so we are going to invoke the Scilla interpreter.

            let Some(g) = gas.checked_sub(SCILLA_INVOKE_RUNNER) else {
                warn!("not enough gas to invoke scilla runner");
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used: (gas_limit - gas).into(),
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(depth, vec![ScillaError::OutOfGas])].into_iter().collect(),
                        exceptions: vec![],
                    },
                    current_state,
                ));
            };
            gas = g;

            let code = code.clone();
            let init_data = init_data.clone();
            let contract_balance = contract.account.balance;

            let (output, mut new_state) = scilla.invoke_contract(
                current_state,
                to_addr,
                &code,
                gas,
                ZilAmount::from_amount(contract_balance),
                &init_data,
                message
                    .as_ref()
                    .ok_or_else(|| anyhow!("call to a Scilla contract without a message"))?,
            )?;
            inspector.call(sender, to_addr, amount.get(), depth);

            let output = match output {
                Ok(o) => o,
                Err(e) => {
                    warn!(?e, "transaction failed");
                    let gas = gas.min(e.gas_remaining);
                    return Ok((
                        ScillaResult {
                            success: false,
                            contract_address: None,
                            logs: vec![],
                            gas_used: (gas_limit - gas).into(),
                            transitions: vec![],
                            accepted: Some(false),
                            errors: [(0, vec![ScillaError::CallFailed])].into_iter().collect(),
                            exceptions: e.errors.into_iter().map(Into::into).collect(),
                        },
                        new_state,
                    ));
                }
            };

            info!(?output);

            gas = gas.min(output.gas_remaining);

            if output.accepted {
                if let Some(result) = new_state.deduct_from_account(sender, amount)? {
                    return Ok((result, new_state));
                }

                let to = new_state.load_account(to_addr)?;
                to.account.balance += amount.get();

                if depth == 0 {
                    root_contract_accepted = true;
                }
            }

            transitions.reserve(output.messages.len());
            call_stack.reserve(output.messages.len());
            for message in output.messages {
                transitions.push(ScillaTransition {
                    from: to_addr,
                    to: message.recipient,
                    depth: depth + 1,
                    amount: message.amount,
                    tag: message.tag.clone(),
                    params: serde_json::to_string(&message.params)?,
                });

                let next_message = json!({
                    "_tag": message.tag,
                    "_amount": message.amount.to_string(),
                    "_sender": format!("{to_addr:#x}"),
                    "_origin": format!("{from_addr:#x}"),
                    "params": message.params,
                });
                call_stack.push((
                    depth + 1,
                    to_addr,
                    message.recipient,
                    message.amount,
                    Some(next_message),
                ));
            }

            logs.reserve(output.events.len());
            for event in output.events {
                let log = ScillaLog {
                    address: to_addr,
                    event_name: event.event_name,
                    params: event
                        .params
                        .into_iter()
                        .map(|p| {
                            Ok(ScillaParam {
                                ty: p.ty,
                                // If the value is a JSON string, don't double encode it.
                                value: if let Value::String(v) = p.value {
                                    v
                                } else {
                                    serde_json::to_string(&p.value)?
                                },
                                name: p.name,
                            })
                        })
                        .collect::<Result<_>>()?,
                };
                logs.push(log);
            }

            state = Some(new_state);
        } else {
            // The `to_addr` is an EOA.
            let Some(g) = gas.checked_sub(SCILLA_TRANSFER) else {
                warn!("not enough gas to make transfer");
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used: (gas_limit - gas).into(),
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(0, vec![ScillaError::OutOfGas])].into_iter().collect(),
                        exceptions: vec![],
                    },
                    current_state,
                ));
            };
            gas = g;

            if let Some(result) = current_state.deduct_from_account(from_addr, amount)? {
                return Ok((result, current_state));
            }

            let to = current_state.load_account(to_addr)?;
            to.account.balance += amount.get();

            inspector.transfer(from_addr, to_addr, amount.get(), depth);

            state = Some(current_state);
        }
    }

    Ok((
        ScillaResult {
            success: true,
            contract_address: None,
            logs,
            gas_used: (gas_limit - gas).into(),
            transitions,
            accepted: Some(root_contract_accepted),
            errors: BTreeMap::new(),
            exceptions: vec![],
        },
        state.take().expect("missing state"),
    ))
}

/// Blessed transactions bypass minimum gas price rules. These transactions have value to the network even at a lower
/// gas price, so we accept them anyway.
const BLESSED_TRANSACTIONS: [Hash; 1] = [
    // Hash of the deployment transaction for the deterministic deployment proxy from
    // https://github.com/Arachnid/deterministic-deployment-proxy. It is valuable to accept this transaction despite
    // the low gas price, because it means the contract is deployed at the same address as other EVM-compatible chains.
    // This means that contracts deployed using this proxy will be deployed to the same address as on other chains.
    Hash(hex!(
        "eddf9e61fb9d8f5111840daef55e5fde0041f5702856532cdbb5a02998033d26"
    )),
];
