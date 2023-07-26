//! Manages execution of transactions on state.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use ethabi::Token;
use evm_ds::evm::{
    backend::{Backend, Basic},
    tracing::EventListener,
};
use evm_ds::evm_server_run::EvmCallArgs;
use evm_ds::protos::Evm::{Continuation, EvmResult};
use evm_ds::{
    continuations::Continuations,
    evm_server_run::{calculate_contract_address, run_evm_impl_direct},
};
use primitive_types::{H160, H256, U256};
use crate::evm_backend::EvmBackend;
use tracing::{error, info, trace};

use crate::state::SignedTransaction;
use crate::{
    contracts,
    message::BlockHeader,
    state::{Address, Log, State},
    time::SystemTime,
};

#[derive(Default)]
pub struct TouchedAddressEventListener {
    pub touched: HashSet<H160>,
}

impl EventListener for TouchedAddressEventListener {
    fn event(&mut self, event: evm_ds::evm::tracing::Event<'_>) {
        match event {
            evm_ds::evm::tracing::Event::Call {
                code_address,
                transfer,
                ..
            } => {
                self.touched.insert(code_address);
                if let Some(transfer) = transfer {
                    self.touched.insert(transfer.source);
                    self.touched.insert(transfer.target); // TODO: Figure out if `transfer.target` is always equal to `code_address`?
                }
            }
            evm_ds::evm::tracing::Event::Create {
                caller, address, ..
            } => {
                self.touched.insert(caller);
                self.touched.insert(address);
            }
            evm_ds::evm::tracing::Event::Suicide {
                address, target, ..
            } => {
                self.touched.insert(address);
                self.touched.insert(target);
            }
            evm_ds::evm::tracing::Event::Exit { .. } => {}
            evm_ds::evm::tracing::Event::TransactCall {
                caller, address, ..
            } => {
                self.touched.insert(caller);
                self.touched.insert(address);
            }
            evm_ds::evm::tracing::Event::TransactCreate {
                caller, address, ..
            } => {
                self.touched.insert(caller);
                self.touched.insert(address);
            }
            evm_ds::evm::tracing::Event::TransactCreate2 {
                caller, address, ..
            } => {
                self.touched.insert(caller);
                self.touched.insert(address);
            }
            evm_ds::evm::tracing::Event::PrecompileSubcall {
                code_address,
                transfer,
                ..
            } => {
                self.touched.insert(code_address);
                if let Some(transfer) = transfer {
                    self.touched.insert(transfer.source);
                    self.touched.insert(transfer.target);
                }
            }
        }
    }
}

/// Data returned after applying a [Transaction] to [State].
pub struct TransactionApplyResult {
    /// Whether the transaction succeeded and the resulting state changes were persisted.
    pub success: bool,
    /// If the transaction was a contract creation, the address of the resulting contract.
    pub contract_address: Option<Address>,
    /// The logs emitted by the transaction execution.
    pub logs: Vec<Log>,
}

impl State {
    /// Deploy a contract at a fixed address. Used for system contracts which exist at well known addresses.
    pub fn deploy_fixed_contract(&mut self, address: Address, code: Vec<u8>) -> Result<()> {
        let mut account = self.get_account(address)?;
        account.code = code;
        self.save_account(address, account)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_transaction_inner(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        _gas_price: u128,
        gas_limit: u64,
        amount: u128,
        payload: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<(Vec<Log>, EvmResult, Option<H160>)> {
        let apparent_value: U256 = amount.into();
        let caller = from_addr;
        let gas_scaling_factor = 1;
        let estimate = false;
        let is_static = false;
        let context = "".to_string();
        let continuations: Arc<Mutex<Continuations>> = Default::default();
        //let logs: Vec<Log> = Default::default();
        let account = self
            .get_account(to_addr.unwrap_or(Address::ZERO))
            .unwrap_or_default();
        let mut to = to_addr.unwrap_or(Address::ZERO).0;
        let mut created_contract_addr: Option<H160> = None;

        let mut code: Vec<u8> = account.code;
        let mut data: Vec<u8> = payload;

        let mut backend = EvmBackend::new(
            self,
             U256::zero(),
             caller.0,
             chain_id,
             current_block,
        );

        if Address::is_balance_transfer(Address(to)) {
            code = contracts::native_token::CODE.clone();
        }

        // If is contract creation
        if to_addr.is_none() {
            code = data;
            data = vec![];
            to = calculate_contract_address(from_addr.0, &backend);
            created_contract_addr = Some(to);
        }

        let mut continuation_stack = vec![];
        let mut result;

        // Set the first continuation as our current context and then loop while there is still
        // a continuation, pushing onto the stack when there are more continuations
        loop {

            let node_continuation = continuation_stack.pop();

            result = run_evm_impl_direct(EvmCallArgs {
                address: to,
                code: code.clone(),
                data: data.clone(),
                apparent_value,
                gas_limit,
                caller: caller.0,
                gas_scaling_factor,
                scaling_factor: None,
                backend: &backend,
                estimate,
                is_static,
                evm_context: context.clone(),
                node_continuation,
                continuations: continuations.clone(),
                enable_cps: true,
                tx_trace_enabled: false,
                tx_trace: "".to_string(),
            });

            // Apply the results to the backend so they can be used in the next continuation

            println!("We are applying update: {:?}", result);
            backend.apply_update(to_addr, result.apply.iter());

            if continuation_stack.is_empty() {
                break;
            }
        }

        let mut backend_result = backend.get_result();
        backend_result.exit_reason = result.exit_reason.clone();

        Ok((result.logs.clone().into_iter().map(|l| l.into()).collect(), backend_result, created_contract_addr))
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction(
        &mut self,
        txn: SignedTransaction,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash();
        info!(?hash, "executing txn");

        let result = self.apply_transaction_inner(
            txn.from_addr,
            txn.transaction.to_addr,
            txn.transaction.gas_price,
            100000000000000, // Workaround until gas is implemented.
            txn.transaction.amount,
            txn.transaction.payload,
            chain_id,
            current_block,
        );

        match result {
            Ok((mut logs, result, contract_addr)) => {
                // Apply the state changes only if success
                let success = result.exit_reason.clone().unwrap().has_succeed();

                if success {
                    if let Some(contract_addr) = contract_addr {
                        let mut acct = self.get_account(Address(contract_addr)).unwrap_or_default();
                        acct.code = result.return_value.clone().to_vec();
                        self.save_account(Address(contract_addr), acct)?;
                    }

                    self.apply_delta( txn.transaction.to_addr, result.apply.iter())?;
                }

                // Note that success can be false, the tx won't apply changes, but the nonce increases
                // and we get the return value (which will indicate the error)
                let mut acct = self.get_account(txn.from_addr).unwrap();
                acct.nonce = acct.nonce.checked_add(1).unwrap();
                self.save_account(txn.from_addr, acct)?;

                info!(?hash, "finished executing txn");
                Ok(TransactionApplyResult {
                    success,
                    contract_address: contract_addr.map(Address),
                    logs,
                })
            }
            Err(e) => {
                error!("Error applying transaction: {:?}", e);

                Ok(TransactionApplyResult {
                    success: false,
                    contract_address: None,
                    logs: Default::default(),
                })
            }
        }
    }

    // Apply the changes the EVM is requesting for
    fn apply_delta<'a>(
        &mut self,
        to_addr: Option<Address>,
        applys: impl Iterator<Item = &'a evm_ds::protos::Evm::Apply>,
    ) -> Result<()> {
        for apply in applys {
            if apply.has_modify() {
                let modify = apply.get_modify();

                let address = Address(modify.get_address().into());
                let balance: U256 = modify.get_balance().into();
                let code = modify.code.clone();
                let _nonce: U256 = modify.get_nonce().into();
                let storage = modify.storage.clone().into_iter();
                let reset_storage = modify.reset_storage;

                // If the `to_addr` was `Address::NATIVE_TOKEN`, then this transaction was a call to the native
                // token contract. Avoid applying further updates to the native balance in this case, which would
                // result in an endless recursion.
                // FIXME: This makes it impossible to charge gas for calls to `Address::NATIVE_TOKEN`.
                // FIXME: We ignore the change if the balance is zero. According to the SputnikVM example code,
                // this is the intended implementation. However, that might mean it is impossible to tell the
                // difference between an account that has been fully drained and an account whose balance has not
                // been changed. We should investigate if this is really an issue.
                if let Some(to_addr) = to_addr {
                    if to_addr != Address::NATIVE_TOKEN && !balance.is_zero() {
                        self.set_native_balance(address, balance)?;
                    }
                }

                let mut account = self.get_account(address).unwrap_or_default();

                if !code.is_empty() {
                    account.code = code.to_vec();
                }

                if reset_storage {
                    self.clear_account_storage(address)?;
                }

                self.save_account(address, account)?;

                for item in storage {
                    let index: H256 = H256::from_slice(item.get_key());
                    let value: H256 = H256::from_slice(item.get_value());

                    if value.is_zero() {
                        self.remove_account_storage(address, index)?;
                    } else {
                        self.set_account_storage(address, index, value)?;
                    }
                }
            }

            if apply.has_delete() {
                let delete = apply.get_delete();

                let address = Address(delete.get_address().into());
                self.delete_account(address)?;
            }
        }

        Ok(())
    }

    pub fn get_native_balance(&self, address: Address) -> Result<U256> {
        let data = contracts::native_token::BALANCE_OF
            .encode_input(&[Token::Address(address.0)])
            .unwrap();

        let balance = self.call_contract(
            Address::ZERO,
            Some(Address::NATIVE_TOKEN),
            data,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
        )?;
        let balance = U256::from_big_endian(&balance);

        Ok(balance)
    }

    pub fn set_native_balance(
        &mut self,
        address: Address,
        amount: U256,
    ) -> Result<()> {
        let data = contracts::native_token::SET_BALANCE
            .encode_input(&[Token::Address(address.0), Token::Uint(amount)])
            .unwrap();

        let result = self.apply_transaction_inner(
            Address::ZERO,
            Some(Address::NATIVE_TOKEN),
            u128::MAX,
            u64::MAX,
            0,
            data,
            // The chain ID and current block are not accessed when the native balance is updated, so we just pass in
            // some dummy values.
            0,
            BlockHeader::default(),
        );

        match result {
            Ok((lgs, result, _)) => {
                // Apply the state changes only if success
                let success = result.exit_reason.unwrap().has_succeed();

                if success {
                    self.apply_delta( Some(Address::NATIVE_TOKEN), result.apply.iter())?;
                }

                Ok(())
            }
            Err(e) => {
                panic!("Failed to set balance with error: {:?}", e);
            }
        }
    }

    pub fn call_contract(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<Vec<u8>> {
        let result = self.apply_transaction_inner(
            from_addr,
            to_addr,
            0,
            u64::MAX,
            0,
            data,
            chain_id,
            current_block,
        );

        result.map(|ret| ret.1.return_value.into())
    }
}
