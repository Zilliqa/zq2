//! Manages execution of transactions on state.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use crate::evm_backend::EvmBackend;
use anyhow::Result;
use ethabi::Token;
use evm_ds::{
    evm::{backend::Backend, tracing::EventListener},
    evm_server_run::{calculate_contract_address, run_evm_impl_direct},
    protos::evm_proto as EvmProto,
};
use primitive_types::{H160, U256};
use tracing::*;

use crate::state::SignedTransaction;
use crate::{
    contracts,
    message::BlockHeader,
    state::{Address, State},
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
    pub logs: Vec<EvmProto::Log>,
}

impl State {
    /// Deploy a contract at a fixed address. Used for system contracts which exist at well known addresses.
    pub fn deploy_fixed_contract(&mut self, address: Address, code: Vec<u8>) -> Result<()> {
        let mut account = self.get_account(address)?;
        account.code = code;
        self.save_account(address, account)
    }

    // Call this function with your transaction and it will return
    #[allow(clippy::too_many_arguments)]
    fn apply_transaction_inner(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        _gas_price: u128,
        gas_limit: u64,
        _amount: u128,
        payload: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<(EvmProto::EvmResult, Option<H160>)> {
        let caller = from_addr;
        let gas_scaling_factor = 1;
        let estimate = false;
        let is_static = false;
        let context = "".to_string();
        let continuations: Arc<Mutex<EvmProto::Continuations>> = Default::default();
        let account = self
            .get_account(to_addr.unwrap_or(Address::ZERO))
            .unwrap_or_default();
        let mut to = to_addr.unwrap_or(Address::ZERO).0;
        let mut created_contract_addr: Option<H160> = None;

        let mut code: Vec<u8> = account.code;
        let mut data: Vec<u8> = payload;

        let mut backend = EvmBackend::new(self, U256::zero(), caller.0, chain_id, current_block);

        // If is contract creation
        if to_addr.is_none() {
            code = data;
            data = vec![];
            to = calculate_contract_address(from_addr.0, &backend);
            created_contract_addr = Some(to);
        }

        let mut continuation_stack: Vec<EvmProto::EvmCallArgs> = vec![EvmProto::EvmCallArgs {
            address: to,
            code,
            data,
            apparent_value: U256::zero(),
            gas_limit,
            caller: caller.0,
            gas_scaling_factor,
            scaling_factor: None,
            estimate,
            is_static,
            evm_context: context,
            node_continuation: None,
            continuations: continuations.clone(),
            enable_cps: true,
            tx_trace_enabled: false,
            tx_trace: "".to_string(),
        }];
        let mut result;

        // Set the first continuation as our current context and then loop while there is still
        // a continuation, pushing onto the stack when there are more continuations
        loop {
            let mut call_args = continuation_stack.pop().unwrap();

            backend.origin = call_args.caller;
            result = run_evm_impl_direct(call_args.clone(), &backend);

            // Apply the results to the backend so they can be used in the next continuation
            backend.apply_update(to_addr, result.take_apply());

            if result.has_trap() {
                let mut cont =
                    EvmProto::ContinuationFb::new(continuations.lock().unwrap().last_created());

                match result.trap_data.unwrap() {
                    EvmProto::TrapData::Create(_) => {
                        panic!("create trap not implemented")
                    }
                    EvmProto::TrapData::Call(call) => {
                        cont.feedback_type = EvmProto::Type::Call;
                        cont.feedback_data =
                            Some(EvmProto::FeedbackData::CallData(EvmProto::Call {
                                data: Vec::new(),
                                memory_offset: call.memory_offset,
                                offset_len: call.offset_len,
                            }));

                        call_args.node_continuation = Some(cont); // todo: move this.

                        let call_data_next = call.call_data;
                        let call_addr: H160 = call.callee_address;
                        let value: U256 = if let Some(transfer) = call.transfer {
                            transfer.value
                        } else {
                            U256::zero()
                        };

                        let call_args_shim: Option<EvmProto::EvmCallArgs> = if !value.is_zero() {
                            let balance_data = contracts::native_token::SET_BALANCE
                                .encode_input(&[Token::Address(call_addr), Token::Uint(value)])
                                .unwrap();

                            Some(EvmProto::EvmCallArgs {
                                caller: Address::ZERO.0,
                                address: Address::NATIVE_TOKEN.0,
                                code: contracts::native_token::CODE.clone(),
                                data: balance_data,
                                gas_limit: u64::MAX,
                                tx_trace: Default::default(),
                                continuations: continuations.clone(),
                                node_continuation: None,
                                evm_context: Default::default(),
                                ..call_args
                            })
                        } else {
                            None
                        };

                        // Fetch the code from the backend
                        let code_next = backend.code(call_addr);

                        // Set up the next continuation, adjust the relevant parameters
                        let call_args_next = EvmProto::EvmCallArgs {
                            address: call_addr,
                            code: code_next,
                            data: call_data_next,
                            tx_trace: Default::default(),
                            continuations: continuations.clone(),
                            node_continuation: None,
                            evm_context: Default::default(),
                            ..call_args
                        };

                        // This is the paused execution, push it back
                        continuation_stack.push(call_args);

                        // Now push on the context we want to execute
                        continuation_stack.push(call_args_next);

                        // If we want to insert a shim, do it here so as to execute first
                        // (shim will increase balance of address)
                        if let Some(call_args_shim) = call_args_shim {
                            continuation_stack.push(call_args_shim);
                        }
                    }
                }
            } else if result.succeeded()
                && !continuation_stack.is_empty()
                && !backend.origin.is_zero()
            {
                // We need to let the continuation prior know the return result
                let prior = continuation_stack.last_mut().unwrap();

                let old_calldata = prior.node_continuation.as_mut().unwrap().get_calldata();
                prior.node_continuation.as_mut().unwrap().feedback_data =
                    Some(EvmProto::FeedbackData::CallData(EvmProto::Call {
                        data: result.return_value.clone(),
                        ..*old_calldata
                    }));
                prior.node_continuation.as_mut().unwrap().succeeded = true;
                prior.node_continuation.as_mut().unwrap().logs = result.logs.clone();
            }

            if continuation_stack.is_empty() {
                break;
            }
        }

        let mut backend_result = backend.get_result();
        backend_result.exit_reason = result.exit_reason;
        backend_result.return_value = result.return_value;
        backend_result.logs = result.logs;

        Ok((backend_result, created_contract_addr))
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction(
        &mut self,
        txn: SignedTransaction,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<TransactionApplyResult> {
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
            Ok((result, contract_addr)) => {
                // Apply the state changes only if success
                let success = result.succeeded();

                if success {
                    if let Some(contract_addr) = contract_addr {
                        let mut acct = self.get_account(Address(contract_addr)).unwrap_or_default();
                        acct.code = result.return_value.to_vec();
                        self.save_account(Address(contract_addr), acct)?;
                    }

                    self.apply_delta(result.apply)?;
                }

                // Note that success can be false, the tx won't apply changes, but the nonce increases
                // and we get the return value (which will indicate the error)
                let mut acct = self.get_account(txn.from_addr).unwrap();
                acct.nonce = acct.nonce.checked_add(1).unwrap();
                self.save_account(txn.from_addr, acct)?;

                Ok(TransactionApplyResult {
                    success,
                    contract_address: contract_addr.map(Address),
                    logs: result.logs,
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
    fn apply_delta(&mut self, applys: Vec<evm_ds::protos::evm_proto::Apply>) -> Result<()> {
        for apply in applys {
            match apply {
                EvmProto::Apply::Delete { .. } => {
                    panic!("We have a delete here");
                }
                EvmProto::Apply::Modify {
                    address,
                    balance: _,
                    nonce: _,
                    code,
                    storage,
                    reset_storage,
                } => {
                    let address = Address(address);
                    let mut account = self.get_account(address).unwrap_or_default();

                    if !code.is_empty() {
                        account.code = code.to_vec();
                    }

                    if reset_storage {
                        self.clear_account_storage(address)?;
                    }

                    self.save_account(address, account)?;

                    for item in storage {
                        if item.value.is_zero() {
                            self.remove_account_storage(address, item.key)?;
                        } else {
                            self.set_account_storage(address, item.key, item.value)?;
                        }
                    }
                }
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

    pub fn set_native_balance(&mut self, address: Address, amount: U256) -> Result<()> {
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
            Ok((result, _)) => {
                // Apply the state changes only if success
                let success = result.succeeded();

                if success {
                    self.apply_delta(result.apply)?;
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

        result.map(|ret| ret.0.return_value)
    }
}
