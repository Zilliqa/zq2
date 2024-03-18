//! Manages execution of transactions on state.

use ethabi::Token;
use std::num::NonZeroU128;

use anyhow::{anyhow, Result};
use eth_trie::Trie;
use primitive_types::{H160, H256, U256};
use revm::{
    primitives::{
        AccountInfo, BlockEnv, Bytecode, BytecodeState, ExecutionResult, HandlerCfg, Output,
        ResultAndState, SpecId, TransactTo, TxEnv, B256, KECCAK_EMPTY,
    },
    Database, Evm,
};
use tracing::*;

use crate::{
    contracts,
    crypto::{Hash, NodePublicKey},
    eth_helpers::extract_revert_msg,
    message::BlockHeader,
    state::{contract_addr, Account, Address, State},
    time::SystemTime,
    transaction::{Log, VerifiedTransaction},
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
    pub gas_used: u64,
}

impl Database for &State {
    type Error = anyhow::Error;

    fn basic(
        &mut self,
        address: revm::primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        let address = H160(address.into_array());

        if !self.try_has_account(address)? {
            return Ok(None);
        }

        let account = self.get_account(address)?;
        let account_info = AccountInfo {
            balance: revm::primitives::U256::from(account.balance),
            nonce: account.nonce,
            code_hash: KECCAK_EMPTY,
            code: Some(Bytecode {
                bytecode: account.code.into(),
                state: BytecodeState::Raw,
            }),
        };

        Ok(Some(account_info))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage(
        &mut self,
        address: revm::primitives::Address,
        index: revm::primitives::U256,
    ) -> Result<revm::primitives::U256, Self::Error> {
        let address = H160(address.into_array());
        let index = H256(index.to_be_bytes());

        let result = self.get_account_storage(address, index)?;

        Ok(revm::primitives::U256::from_be_bytes(result.0))
    }

    fn block_hash(&mut self, _number: revm::primitives::U256) -> Result<B256, Self::Error> {
        // TODO
        Ok(B256::ZERO)
    }
}

pub const BLOCK_GAS_LIMIT: u64 = 84_000_000;
pub const GAS_PRICE: u128 = 4761904800000;

const SPEC_ID: SpecId = SpecId::SHANGHAI;

impl State {
    /// Used primarily during genesis to set up contracts for chain functionality.
    /// If override_address address is set, forces contract deployment to that addess.
    pub(crate) fn force_deploy_contract(
        &mut self,
        creation_bytecode: Vec<u8>,
        override_address: Option<Address>,
    ) -> Result<Address> {
        let ResultAndState { result, mut state } = self.apply_transaction_inner(
            H160::zero(),
            None,
            GAS_PRICE,
            BLOCK_GAS_LIMIT,
            0,
            creation_bytecode,
            None,
            0,
            BlockHeader::genesis(Hash::ZERO),
        )?;

        match result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(addr)),
                ..
            } => {
                let addr = if let Some(override_address) = override_address {
                    let override_address = revm::primitives::Address::from(override_address.0);
                    let account = state
                        .remove(&addr)
                        .ok_or_else(|| anyhow!("deployment did not change the contract account"))?;
                    state.insert(override_address, account);
                    addr
                } else {
                    addr
                };

                self.apply_delta(state)?;
                Ok(H160(addr.into_array()))
            }
            ExecutionResult::Success { .. } => {
                Err(anyhow!("deployment did not create a transaction"))
            }
            ExecutionResult::Revert { .. } => Err(anyhow!("deployment reverted")),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("deployment halted: {reason:?}")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_transaction_inner(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u128,
        gas_limit: u64,
        amount: u128,
        payload: Vec<u8>,
        nonce: Option<u64>,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<ResultAndState> {
        let mut evm = Evm::builder()
            .with_db(self)
            .with_block_env(BlockEnv {
                number: revm::primitives::U256::from(current_block.number),
                coinbase: revm::primitives::Address::ZERO,
                timestamp: revm::primitives::U256::from(
                    current_block
                        .timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                gas_limit: revm::primitives::U256::from(BLOCK_GAS_LIMIT),
                basefee: revm::primitives::U256::from(GAS_PRICE),
                difficulty: revm::primitives::U256::from(1),
                prevrandao: Some(B256::ZERO),
                blob_excess_gas_and_price: None,
            })
            .with_handler_cfg(HandlerCfg { spec_id: SPEC_ID })
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
                gas_limit,
                gas_price: revm::primitives::U256::from(gas_price),
                transact_to: to_addr
                    .map(|a| TransactTo::call(a.0.into()))
                    .unwrap_or_else(TransactTo::create),
                value: revm::primitives::U256::from(amount),
                data: payload.clone().into(),
                nonce,
                chain_id: Some(chain_id),
                access_list: vec![],
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: None,
            })
            .build();

        Ok(evm.transact()?)
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction(
        &mut self,
        txn: VerifiedTransaction,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash;
        let from_addr = txn.signer;
        info!(?hash, ?txn, "executing txn");

        let txn = txn.tx.into_transaction();

        let ResultAndState { result, state } = self.apply_transaction_inner(
            from_addr,
            txn.to_addr(),
            txn.max_fee_per_gas(),
            txn.gas_limit(),
            txn.amount(),
            txn.payload().to_vec(),
            txn.nonce(),
            chain_id,
            current_block,
        )?;

        self.apply_delta(state)?;

        Ok(TransactionApplyResult {
            success: result.is_success(),
            contract_address: if let ExecutionResult::Success {
                output: Output::Create(_, c),
                ..
            } = result
            {
                c.map(|a| H160(a.into_array()))
            } else {
                None
            },
            logs: result
                .logs()
                .into_iter()
                .map(|l| Log {
                    address: H160(l.address.into_array()),
                    topics: l.topics().iter().map(|t| H256(t.0)).collect(),
                    data: l.data.data.to_vec(),
                })
                .collect(),
            gas_used: result.gas_used(),
        })
    }

    pub(crate) fn apply_delta(
        &mut self,
        state: revm::primitives::HashMap<revm::primitives::Address, revm::primitives::Account>,
    ) -> Result<()> {
        for (address, account) in state {
            let address = H160(address.into_array());

            let mut storage = self.get_account_trie(address)?;

            for (index, value) in account.changed_storage_slots() {
                let index = H256(index.to_be_bytes());
                let value = H256(value.present_value().to_be_bytes());
                trace!(?address, ?index, ?value, "update storage");

                storage.insert(&Self::account_storage_key(address, index), value.as_bytes())?;
            }

            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.try_into()?,
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
            };
            trace!(?address, ?account, "update account");
            self.save_account(address, account)?;
        }

        Ok(())
    }

    pub fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        let data = contracts::deposit::GET_STAKERS.encode_input(&[])?;

        let stakers = self.call_contract(
            Address::zero(),
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
            Address::zero(),
            Some(contract_addr::DEPOSIT),
            data,
            0,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
        )?;

        Ok(NonZeroU128::new(U256::from_big_endian(&stake).as_u128()))
    }

    pub fn get_reward_address(&self, public_key: NodePublicKey) -> Result<Option<Address>> {
        let data = contracts::deposit::GET_REWARD_ADDRESS
            .encode_input(&[Token::Bytes(public_key.as_bytes())])?;

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

        let addr = contracts::deposit::GET_REWARD_ADDRESS.decode_output(&return_value)?[0]
            .clone()
            .into_address()
            .unwrap();

        Ok((!addr.is_zero()).then_some(addr))
    }

    pub fn get_total_stake(&self) -> Result<u128> {
        let data = contracts::deposit::TOTAL_STAKE.encode_input(&[])?;

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
        gas: Option<u64>,
        gas_price: Option<u128>,
        value: u128,
    ) -> Result<u64> {
        let gas_price = gas_price.unwrap_or(GAS_PRICE);
        let gas = gas.unwrap_or(BLOCK_GAS_LIMIT);

        let ResultAndState { result, .. } = self.apply_transaction_inner(
            from_addr,
            to_addr,
            gas_price,
            gas,
            value,
            data,
            None,
            chain_id,
            current_block,
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
        let ResultAndState { result, .. } = self.apply_transaction_inner(
            from_addr,
            to_addr,
            GAS_PRICE,
            BLOCK_GAS_LIMIT,
            amount,
            data,
            None,
            chain_id,
            current_block,
        )?;

        match result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Ok(output.to_vec()),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("halted due to: {reason:?}")),
        }
    }
}
