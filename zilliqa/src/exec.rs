//! Manages execution of transactions on state.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use crate::evm_backend::EvmBackend;
use anyhow::{anyhow, Result};
use ethabi::Token;
use evm_ds::{
    evm::{backend::Backend, tracing::EventListener},
    evm_server_run::{
        calculate_contract_address, calculate_contract_address_scheme, run_evm_impl_direct,
    },
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

    // Call this function with your transaction and it will return whether is succeeded and the state deltas that
    // you should apply if you want to commit this transaction.
    //
    // The way it works is by using a continuation passing style. At each point the Tx makes a call,
    // or some other operations,
    // a trap is generated and the Tx is paused (continuation). The continuation is then pushed onto a stack and the next
    // continuation (the call to make) is pushed onto the stack.
    #[allow(clippy::too_many_arguments)]
    fn apply_transaction_inner(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u64,
        gas_limit: u64,
        amount: U256,
        payload: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
        estimate: bool,
        print_enabled: bool,
    ) -> Result<(EvmProto::EvmResult, Option<Address>)> {
        let caller = from_addr;
        let is_static = false;
        let context = "".to_string();
        let continuations: Arc<Mutex<EvmProto::Continuations>> = Default::default();
        let account = self
            .get_account(to_addr.unwrap_or(Address::ZERO))
            .unwrap_or_default();
        let mut to = to_addr.unwrap_or(Address::ZERO);
        let mut created_contract_addr: Option<Address> = None;

        let mut code: Vec<u8> = account.code;
        let mut data: Vec<u8> = payload;

        // The backend is provided to the evm as a way to read accounts and state during execution
        let mut backend = EvmBackend::new(self, U256::zero(), caller.0, chain_id, current_block);

        // if this is none, it is contract creation
        if to_addr.is_none() {
            code = data;
            data = vec![];
            to = Address(calculate_contract_address(from_addr.0, &backend));
            created_contract_addr = Some(to);
            debug!("Calculated contract address for creation: {}", to);
        }

        let mut continuation_stack: Vec<EvmProto::EvmCallArgs> = vec![];
        let native_balance = self.get_native_balance(from_addr, false).unwrap();
        let target_balance = self.get_native_balance(to, false).unwrap();

        // The first continuation in the stack is the tx itself
        continuation_stack.push(EvmProto::EvmCallArgs {
            address: to.0,
            code,
            data,
            apparent_value: amount,
            gas_limit,
            caller: caller.0,
            gas_scaling_factor: 1,
            scaling_factor: None,
            estimate,
            is_static,
            evm_context: context,
            node_continuation: None,
            continuations: continuations.clone(),
            enable_cps: true,
            tx_trace_enabled: false,
            tx_trace: "".to_string(),
        });
        let mut result;
        let mut run_succeeded;

        // For gas, we need to check that the caller has enough balance to pay for the gas and the
        // transfer (gas price). After execution, we can then deduct the gas used from the caller's balance.
        let gas_cost_max: U256 = (gas_price + gas_limit).into();
        let upfront_reserve = if estimate {
            amount
        } else {
            gas_cost_max + amount
        };

        // Check the sender has enough balance and deduct it before any other operations happen, sending
        // it to the destination address or contract creation address
        if gas_price > 0 && native_balance <= upfront_reserve {
            let error_str = format!(
                "Transaction attempted to use more funds \
             and gas than it actually had! Amount: {}, Balance: {}, gas_price: {}, \
              addr: {}",
                upfront_reserve, native_balance, gas_price, from_addr
            );
            warn!(error_str);
            return Err(anyhow!(error_str));
        }

        // If the contract is to have funds during its execution, we need to push a transfer from
        // the sender to the contract onto the stack to execute first
        if amount > U256::zero() {
            if print_enabled {
                debug!(
                    "During execution: populating account {}->{} with balance: {}",
                    from_addr, to, amount
                );
                debug!(
                    "Prior balances:  {} and {} ",
                    native_balance, target_balance
                );
            }

            continuation_stack.push(push_transfer(from_addr, to, amount, continuations.clone()));
        }

        if print_enabled {
            debug!(
                "*** Evm invocation begin - with args {:?}",
                continuation_stack
            );
        }

        // Set the first continuation as our current context and then loop while there is still
        // a continuation, pushing onto the stack when there are more continuations
        loop {
            let mut call_args = continuation_stack.pop().unwrap();

            if print_enabled {
                debug!("Running execution loop...");
            }

            backend.origin = call_args.caller;
            result = run_evm_impl_direct(call_args.clone(), &backend);

            if print_enabled {
                info!("Evm invocation complete - applying result {:?}", result);
            }

            // Apply the results to the backend so they can be used in the next continuation
            backend.apply_update(result.take_apply());
            run_succeeded = result.succeeded();

            // Handle potential traps. The continuation which was executing needs to get its
            // feedback set for when it resumes
            if result.has_trap() {
                let mut cont =
                    EvmProto::ContinuationFb::new(continuations.lock().unwrap().last_created());

                match result.trap_data.unwrap() {
                    EvmProto::TrapData::Create(create) => {
                        let addr_to_create =
                            calculate_contract_address_scheme(create.scheme, &backend);

                        cont.feedback_type = EvmProto::Type::Create;
                        cont.feedback_data = Some(EvmProto::FeedbackData::Address(addr_to_create));

                        call_args.node_continuation = Some(cont);

                        // Set up the next continuation, adjust the relevant parameters
                        let call_args_next = EvmProto::EvmCallArgs {
                            caller: create.caller,
                            address: addr_to_create,
                            code: vec![],
                            data: create.call_data,
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
                    }
                    EvmProto::TrapData::Call(call) => {
                        cont.feedback_type = EvmProto::Type::Call;
                        cont.feedback_data =
                            Some(EvmProto::FeedbackData::CallData(EvmProto::Call {
                                data: Vec::new(),
                                memory_offset: call.memory_offset,
                                offset_len: call.offset_len,
                            }));

                        call_args.node_continuation = Some(cont);

                        let call_data_next = call.call_data;
                        let call_addr: Address = call.callee_address.into();
                        let caller: Address = call.context.caller.into();
                        let value: U256 = if let Some(transfer) = call.transfer {
                            transfer.value
                        } else {
                            U256::zero()
                        };

                        // Fetch the code to be called from the backend
                        let code_next = backend.code(call_addr.0);

                        // Set up the next continuation, adjust the relevant parameters
                        let call_args_next = EvmProto::EvmCallArgs {
                            address: call_addr.0,
                            code: code_next,
                            data: call_data_next,
                            apparent_value: value,
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

                        // If the call also has a value transfer, we need to execute that first
                        if !value.is_zero() {
                            continuation_stack.push(push_transfer(
                                caller,
                                call_addr,
                                value,
                                continuations.clone(),
                            ));
                        }
                    }
                }
            } else if !continuation_stack.is_empty() && !backend.origin.is_zero() {
                if !run_succeeded {
                    warn!(
                        "Tx failed to execute! Call context: {}",
                        call_args.evm_context
                    );

                    if call_args.evm_context == "fund_transfer".to_string() {
                        continuation_stack.pop();
                    }
                }

                // We need to let the continuation prior know the return result
                let prior = continuation_stack.last_mut().unwrap();

                // Check whether we completed a call or a create trap just now
                let prior_node_continuation = prior.node_continuation.as_mut();

                if let Some(prior_node_continuation) = prior_node_continuation {
                    match prior_node_continuation.feedback_type {
                        EvmProto::Type::Call => {
                            let old_calldata = prior_node_continuation.get_calldata();
                            prior_node_continuation.feedback_data =
                                Some(EvmProto::FeedbackData::CallData(EvmProto::Call {
                                    data: result.return_value.clone(),
                                    ..*old_calldata
                                }));
                            prior_node_continuation.succeeded = run_succeeded;
                            prior_node_continuation.logs = result.logs.clone();
                        }
                        EvmProto::Type::Create => {
                            prior_node_continuation.feedback_data =
                                Some(EvmProto::FeedbackData::Address(
                                    prior_node_continuation.get_address(),
                                ));
                            prior_node_continuation.succeeded = run_succeeded;
                            prior_node_continuation.logs = result.logs.clone();
                        }
                    }
                }
            }

            // We have finished looping, break
            if continuation_stack.is_empty() {
                break;
            }
        }

        // Finally, we want to deduct the gas used by the caller and send it to the miner
        // For now we send it to origin and assume we will handle rewards later
        // In estimation mode, we do not attempt to deduct the gas (so we should use this mode for
        // system calls)
        if !estimate && run_succeeded {
            if result.remaining_gas > gas_limit {
                panic!("More gas remains than we specified at the beginning of execution!");
            }

            let gas_deduction = gas_limit - result.remaining_gas + gas_price;

            continuation_stack.push(push_transfer(
                from_addr,
                Address::COLLECTED_FEES,
                gas_deduction.into(),
                continuations,
            ));
            let call_args = continuation_stack.pop().unwrap();

            if print_enabled {
                debug!("Applying gas deduction of {}", gas_deduction);
                debug!(
                    "our balance is: {}",
                    self.get_native_balance(from_addr, false).unwrap()
                );
                debug!("our caller is: {}", call_args.caller);
            }

            backend.origin = call_args.caller;
            let mut gas_result = run_evm_impl_direct(call_args, &backend);

            if !gas_result.succeeded() {
                let fail_string = format!(
                    "Gas deduction FAILED with error: {:?}",
                    gas_result.exit_reason
                );
                warn!(fail_string);
                return Err(anyhow!(fail_string));
            }

            backend.apply_update(gas_result.take_apply());
        }

        // If this was contract creation, apply this to the deltas for the convenience of
        // the caller
        if let Some(created_contract_addr) = created_contract_addr {
            backend.create_account(created_contract_addr, result.return_value.clone());
        }

        let mut backend_result = backend.get_result();
        backend_result.exit_reason = result.exit_reason;
        backend_result.return_value = result.return_value;
        backend_result.remaining_gas = result.remaining_gas;
        backend_result.logs = result.logs;

        if print_enabled {
            debug!(
                "*** Loop complete - returning final results {:?} {:?}",
                backend_result, created_contract_addr
            );
        }

        Ok((backend_result, created_contract_addr))
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction(
        &mut self,
        txn: SignedTransaction,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash();
        info!(?hash, ?txn, "executing txn");

        let gas_price = self.get_gas_price()?;

        if txn.transaction.gas_limit < gas_price {
            let error_str = format!(
                "Transaction gas limit is less than the gas price! Tx limit: {}, Gas price: {}",
                txn.transaction.gas_limit, gas_price
            );
            warn!(error_str);
        }

        let result = self.apply_transaction_inner(
            txn.from_addr,
            txn.transaction.to_addr,
            txn.transaction.gas_price,
            txn.transaction.gas_limit,
            txn.transaction.amount.into(),
            txn.transaction.payload,
            chain_id,
            current_block,
            false,
            true,
        );

        match result {
            Ok((result, contract_addr)) => {
                // Apply the state changes only if success
                let success = result.succeeded();

                if success {
                    self.apply_delta(result.apply)?;
                }

                // Note that success can be false, the tx won't apply changes, but the nonce increases
                // and we get the return value (which will indicate the error)
                let mut acct = self.get_account(txn.from_addr).unwrap();
                acct.nonce = acct.nonce.checked_add(1).unwrap();
                self.save_account(txn.from_addr, acct)?;

                Ok(TransactionApplyResult {
                    success,
                    contract_address: contract_addr,
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
                EvmProto::Apply::Delete { address } => {
                    let address = Address(address);
                    let _account = self.delete_account(address);
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

    pub fn get_native_balance(&self, address: Address, print_enabled: bool) -> Result<U256> {
        // For these accounts, we hardcode the balance we return to the EVM engine as zero. Otherwise, we have an
        // infinite recursion because getting the native balance of any account requires this method to be called for
        // these two 'special' accounts.
        if address == Address::NATIVE_TOKEN || address == Address::ZERO {
            return Ok(U256::zero());
        }

        let data = contracts::native_token::BALANCE_OF
            .encode_input(&[Token::Address(address.0)])
            .unwrap();

        if print_enabled {
            debug!("Calling contract to get balance...");
        }

        let balance = self.call_contract(
            Address::ZERO,
            Some(Address::NATIVE_TOKEN),
            data,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
            print_enabled,
        )?;
        let balance = U256::from_big_endian(&balance);

        trace!("Queried balance of addr {} is: {}", address, balance);

        Ok(balance)
    }

    pub fn set_gas_price(&mut self, price: U256) -> Result<()> {
        let data = contracts::gas_price::SET_GAS
            .encode_input(&[Token::Uint(price)])
            .unwrap();

        debug!("****** setting gas price to: {}", price);

        let result = self.apply_transaction_inner(
            Address::ZERO,
            Some(Address::GAS_PRICE),
            u64::MIN,
            u64::MAX,
            U256::zero(),
            data,
            // The chain ID and current block are not accessed when the native balance is updated, so we just pass in
            // some dummy values.
            0,
            BlockHeader::default(),
            true,
            false,
        );

        match result {
            Ok((result, _)) => {
                // Apply the state changes only if success
                let success = result.succeeded();

                if success {
                    self.apply_delta(result.apply)?;
                } else {
                    panic!(
                        "Failed to set gas price with error: {:?}",
                        result.exit_reason
                    );
                }

                Ok(())
            }
            Err(e) => {
                panic!("Failed to set gas with error: {:?}", e);
            }
        }
    }

    pub fn get_gas_price(&self) -> Result<u64> {
        let data = contracts::gas_price::GET_GAS.encode_input(&[]).unwrap();

        let gas_price = self.call_contract(
            Address::ZERO,
            Some(Address::GAS_PRICE),
            data,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
            false,
        )?;
        let gas_price = U256::from_big_endian(&gas_price);

        trace!("Queried GAS! is: {}", gas_price);

        Ok(gas_price.as_u64())
    }

    pub fn set_native_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        let data = contracts::native_token::SET_BALANCE
            .encode_input(&[Token::Address(address.0), Token::Uint(amount)])
            .unwrap();

        debug!(
            "****** Setting native balance of {} to: {}",
            address, amount
        );

        let result = self.apply_transaction_inner(
            Address::ZERO,
            Some(Address::NATIVE_TOKEN),
            u64::MIN,
            u64::MAX,
            U256::zero(),
            data,
            // The chain ID and current block are not accessed when the native balance is updated, so we just pass in
            // some dummy values.
            0,
            BlockHeader::default(),
            true,
            false,
        );

        match result {
            Ok((result, _)) => {
                // Apply the state changes only if success
                let success = result.succeeded();

                if success {
                    self.apply_delta(result.apply)?;
                } else {
                    panic!("Failed to set balance with error: {:?}", result.exit_reason);
                }

                Ok(())
            }
            Err(e) => {
                panic!("Failed to set balance with error: {:?}", e);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
        print_enabled: bool,
        gas: u64,
        _gas_price: u64,
        value: U256,
    ) -> Result<u64> {
        if print_enabled {
            debug!("estimating gas from: {:?} to: {:?}", from_addr, to_addr);
        }

        Ok(1001014 * 2)

        //        let gas_price = self.get_gas_price()?;
        //
        //        let result = self.apply_transaction_inner(
        //            from_addr,
        //            to_addr,
        //            0,
        //            gas,
        //            value,
        //            data,
        //            chain_id,
        //            current_block,
        //            true,
        //            print_enabled,
        //        );
        //
        //        if print_enabled {
        //            debug!("finished contact gas estimation");
        //        }
        //
        //        match result {
        //            Ok((result, _)) => {
        //                if !result.succeeded() {
        //                    let error_str =
        //                        format!("Estimate gas failed with error: {:?}", result.exit_reason);
        //                    warn!(error_str);
        //                    return Err(anyhow!(error_str));
        //                }
        //
        //                if result.remaining_gas > gas {
        //                    let error_str = format!("More gas remaining than was specified in the estimate! Remaining gas: {} Provided: {}", result.remaining_gas, gas);
        //                    warn!(error_str);
        //                    return Err(anyhow!(error_str));
        //                }
        //
        //                let res = gas - result.remaining_gas + gas_price;
        //
        //                info!(
        //                    "gas estimation: {} {} {} -> {}",
        //                    gas, result.remaining_gas, gas_price, res
        //                );
        //
        //                Ok(res)
        //            }
        //            Err(e) => {
        //                let error_str = format!("Estimate gas failed with error: {:?}", e);
        //                warn!(error_str);
        //                Err(anyhow!(error_str))
        //            }
        //        }
    }

    pub fn call_contract(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
        print_enabled: bool,
    ) -> Result<Vec<u8>> {
        if print_enabled {
            debug!("Calling contract from: {:?} to: {:?}", from_addr, to_addr);
        }

        let result = self.apply_transaction_inner(
            from_addr,
            to_addr,
            0,
            u64::MAX,
            U256::zero(),
            data,
            chain_id,
            current_block,
            true,
            print_enabled,
        );

        if print_enabled {
            debug!("finished contact call");
        }

        result.map(|ret| ret.0.return_value)
    }
}

// Convenience function to create a balance transfer for the call stack. Note we do NOT use the
// setBalance function as this should only be used at genesis
pub fn push_transfer(
    from: Address,
    to: Address,
    amount: U256,
    continuations: Arc<Mutex<EvmProto::Continuations>>,
) -> EvmProto::EvmCallArgs {
    trace!(
        "Pushing transfer from: {} -> to: {} amount: {}",
        from,
        to,
        amount
    );

    let balance_data = contracts::native_token::TRANSFER
        .encode_input(&[Token::Address(to.0), Token::Uint(amount)])
        .unwrap();

    EvmProto::EvmCallArgs {
        caller: from.0,
        gas_scaling_factor: 1,
        scaling_factor: None,
        estimate: false,
        address: Address::NATIVE_TOKEN.0,
        code: contracts::native_token::CODE.clone(),
        data: balance_data,
        apparent_value: Default::default(),
        gas_limit: u64::MAX,
        tx_trace: Default::default(),
        continuations,
        enable_cps: true,
        node_continuation: None,
        evm_context: "fund_transfer".to_string(),
        is_static: false,
        tx_trace_enabled: false,
    }
}
