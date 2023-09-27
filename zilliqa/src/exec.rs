//! Manages execution of transactions on state.

use std::{collections::HashSet, rc::Rc};

use anyhow::{anyhow, Result};
use ethabi::Token;
use evm::{
    backend::{Apply, Basic, Log},
    executor::stack::{MemoryStackState, StackExecutor, StackState, StackSubstateMetadata},
    Config, Context, CreateScheme, ExitReason, Runtime,
};
use evm_ds::{evm::tracing::EventListener, protos::evm_proto};
use primitive_types::{H160, H256, U256};
use tracing::*;

use crate::{
    contracts,
    crypto::Hash,
    message::BlockHeader,
    state::{contract_addr, Address, State},
    time::SystemTime,
    transaction::VerifiedTransaction,
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
    pub logs: Vec<evm_proto::Log>,
    /// The gas paid by the transaction
    pub gas_used: u64,
}

impl TransactionApplyResult {
    fn failed(gas_used: u64) -> TransactionApplyResult {
        TransactionApplyResult {
            success: false,
            contract_address: None,
            logs: vec![],
            gas_used,
        }
    }
}

const CONFIG: Config = Config::shanghai();

impl State {
    /// Deploy a contract to a pre-specified address, used at genesis to deploy system contracts.
    pub(crate) fn deploy_genesis_contract(
        &mut self,
        address: Address,
        creation_bytecode: Vec<u8>,
    ) -> Result<()> {
        let gas_limit = 1000000000000000;
        let context =
            self.call_context(0.into(), H160::zero(), 0, BlockHeader::genesis(Hash::ZERO));
        let mut executor = self.executor(&context, gas_limit);

        let context = Context {
            address: address,
            caller: H160::zero(),
            apparent_value: U256::zero(),
        };
        let mut runtime = Runtime::new(
            Rc::new(creation_bytecode),
            Rc::new(Vec::new()),
            context,
            CONFIG.stack_limit,
            CONFIG.memory_limit,
        );
        let exit_reason = match runtime.run(&mut executor) {
            evm::Capture::Exit(e) => e,
            evm::Capture::Trap(_) => {
                return Err(anyhow!("unexpected trap in contract deployment"));
            }
        };
        match exit_reason {
            ExitReason::Succeed(_) => {}
            _ => {
                return Err(anyhow!("deployment failed: {exit_reason:?}"));
            }
        }
        let return_data = runtime.machine().return_value();
        executor.state_mut().set_code(address, return_data);
        let (applys, _) = executor.into_state().deconstruct();
        // `applys` borrows from `self`. Clone it so that we can mutate `self`.
        let applys: Vec<_> = applys
            .into_iter()
            .map(|a| match a {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => Apply::Modify {
                    address,
                    basic,
                    code,
                    storage: storage.into_iter().collect::<Vec<_>>(),
                    reset_storage,
                },
                Apply::Delete { address } => Apply::Delete { address },
            })
            .collect();
        self.apply_delta(None, applys)?;

        Ok(())
    }

    // Call this function with your transaction and it will return whether is succeeded and the state deltas that
    // you should apply if you want to commit this transaction.
    //
    // The way it works is by using a continuation passing style. At each point the Tx makes a call,
    // or some other operations,
    // a trap is generated and the Tx is paused (continuation). The continuation is then pushed onto a stack and the next
    // continuation (the call to make) is pushed onto the stack.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_transaction_inner(
        &mut self,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u128,
        gas_limit: u64,
        amount: U256,
        payload: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
        _tracing: bool,
        estimate: bool,
        _print_enabled: bool,
    ) -> Result<TransactionApplyResult> {
        println!("exec: {from_addr} -> {to_addr:?}, gas_price: {gas_price}, gas_limit: {gas_limit}, estimate: {estimate}");
        let context = self.call_context(gas_price.into(), from_addr, chain_id, current_block);
        let mut executor = self.executor(&context, gas_limit);

        let (exit_reason, contract_address) = if let Some(to_addr) = to_addr {
            // Contract call
            let (exit_reason, _) =
                executor.transact_call(from_addr, to_addr, amount, payload, gas_limit, vec![]);
            (exit_reason, None)
        } else {
            // Contract creation
            let address = executor.create_address(CreateScheme::Legacy { caller: from_addr });
            let (exit_reason, _) =
                executor.transact_create(from_addr, amount, payload, gas_limit, vec![]);
            (exit_reason, Some(address))
        };

        let gas_used = executor.used_gas().min(gas_limit);

        let (applys, logs) = executor.into_state().deconstruct();
        // `applys` borrows from `self`. Clone it so that we can mutate `self`.
        let applys: Vec<_> = applys
            .into_iter()
            .map(|a| match a {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => Apply::Modify {
                    address,
                    basic,
                    code,
                    storage: storage.into_iter().collect::<Vec<_>>(),
                    reset_storage,
                },
                Apply::Delete { address } => Apply::Delete { address },
            })
            .collect();
        let logs: Vec<_> = logs
            .into_iter()
            .map(|log| Log {
                address: log.address,
                topics: log.topics,
                data: log.data,
            })
            .collect();

        if !from_addr.is_zero()
        {
            let current = self.get_native_balance(from_addr, false)?;
            let fee = U256::from(gas_used) * U256::from(gas_price);
            println!("Deducting {fee:?} from current balance of {current:?}");
            self.set_native_balance(from_addr, current - fee)?;
        }

        match exit_reason {
            ExitReason::Succeed(_) => {}
            ExitReason::Error(_) | ExitReason::Revert(_) => {
                return Ok(TransactionApplyResult::failed(gas_used));
            }
            ExitReason::Fatal(e) => {
                return Err(anyhow!("EVM fatal error: {e:?}"));
            }
        }

        self.apply_delta(to_addr, applys)?;

        info!(?contract_address, "transaction processed");

        Ok(TransactionApplyResult {
            success: true,
            contract_address,
            logs,
            gas_used,
        })
    }

    /// Helper wrapper around apply_transaction_inner when only the EVM payload matters
    /// Used for internal system transactions
    pub(crate) fn force_execute_payload(
        &mut self,
        to_addr: Option<Address>,
        payload: Vec<u8>,
    ) -> Result<TransactionApplyResult> {
        self.apply_transaction_inner(
            Address::zero(),
            to_addr,
            u128::MIN,
            u64::MAX,
            U256::zero(),
            payload,
            0,
            BlockHeader::default(),
            false,
            true,
            false,
        )
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction(
        &mut self,
        txn: VerifiedTransaction,
        chain_id: u64,
        current_block: BlockHeader,
        tracing: bool,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash;
        let from_addr = txn.signer;
        info!(?hash, ?txn, "executing txn");

        let txn = txn.tx.into_transaction();

        self.apply_transaction_inner(
            from_addr,
            txn.to_addr(),
            txn.max_fee_per_gas(),
            txn.gas_limit(),
            txn.amount().into(),
            txn.payload().to_vec(),
            chain_id,
            current_block,
            tracing,
            false,
            true,
        )
    }

    fn apply_delta(
        &mut self,
        to_addr: Option<Address>,
        applys: Vec<evm::backend::Apply<Vec<(H256, H256)>>>,
    ) -> Result<()> {
        for apply in applys {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => {
                    // If the `to_addr` was `Address::NATIVE_TOKEN`, then this transaction was a call to the native
                    // token contract. Avoid applying further updates to the native balance in this case, which would
                    // result in an endless recursion.
                    // FIXME: This makes it impossible to charge gas for calls to `Address::NATIVE_TOKEN`.
                    // FIXME: We ignore the change if the balance is zero. According to the SputnikVM example code,
                    // this is the intended implementation. However, that might mean it is impossible to tell the
                    // difference between an account that has been fully drained and an account whose balance has not
                    // been changed. We should investigate if this is really an issue.
                    if to_addr
                        .map(|a| a != contract_addr::NATIVE_TOKEN)
                        .unwrap_or(true)
                        && !basic.balance.is_zero()
                    {
                        self.set_native_balance(address, basic.balance)?;
                    }

                    let mut account = self.get_account(address)?;
                    if let Some(code) = code {
                        account.code = code;
                    }
                    account.nonce = basic.nonce.as_u64();
                    self.save_account(address, account)?;

                    if reset_storage {
                        self.clear_account_storage(address)?;
                    }

                    for (index, value) in storage {
                        if value.is_zero() {
                            self.remove_account_storage(address, index)?;
                        } else {
                            self.set_account_storage(address, index, value)?;
                        }
                    }
                }
                Apply::Delete { address } => {
                    self.delete_account(address)?;
                }
            }
        }

        Ok(())
    }

    pub fn get_native_balance(&self, address: Address, print_enabled: bool) -> Result<U256> {
        // For these accounts, we hardcode the balance we return to the EVM engine as zero. Otherwise, we have an
        // infinite recursion because getting the native balance of any account requires this method to be called for
        // these two 'special' accounts.
        if address == contract_addr::NATIVE_TOKEN || address.is_zero() {
            return Ok(U256::zero());
        }

        let data = contracts::native_token::BALANCE_OF
            .encode_input(&[Token::Address(address)])
            .unwrap();

        if print_enabled {
            debug!("Calling contract to get balance...");
        }

        let balance = self.call_contract(
            Address::zero(),
            Some(contract_addr::NATIVE_TOKEN),
            data,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            U256::zero(),
            0,
            BlockHeader::default(),
            false,
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
        let result = self.force_execute_payload(Some(contract_addr::GAS_PRICE), data)?;

        if !result.success {
            return Err(anyhow!(
                "setting gas price failed, this should never happen"
            ));
        }

        Ok(())
    }

    pub fn get_gas_price(&self) -> Result<u64> {
        let data = contracts::gas_price::GET_GAS.encode_input(&[]).unwrap();

        let gas_price = self.call_contract(
            Address::zero(),
            Some(contract_addr::GAS_PRICE),
            data,
            U256::zero(),
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::default(),
            false,
            false,
        )?;
        let gas_price = U256::from_big_endian(&gas_price);

        trace!("Queried GAS! is: {}", gas_price);

        Ok(gas_price.as_u64())
    }

    pub fn set_native_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        let data = contracts::native_token::SET_BALANCE
            .encode_input(&[Token::Address(address), Token::Uint(amount)])
            .unwrap();

        debug!(
            "****** Setting native balance of {} to: {}",
            address, amount
        );

        let result = self.apply_transaction_inner(
            Address::zero(),
            Some(contract_addr::NATIVE_TOKEN),
            u128::MIN,
            u64::MAX,
            U256::zero(),
            data,
            // The chain ID and current block are not accessed when the native balance is updated, so we just pass in
            // some dummy values.
            0,
            BlockHeader::default(),
            false,
            true,
            false,
        )?;

        if !result.success {
            return Err(anyhow!(
                "setting native balance failed, this should never happen"
            ));
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &mut self,
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

        let result = self.apply_transaction_inner(
            from_addr,
            to_addr,
            0,
            gas,
            value,
            data,
            chain_id,
            current_block,
            false,
            true,
            print_enabled,
        )?;

        if !result.success {
            return Err(anyhow!("estimate gas failed, this should never happen"));
        }

        Ok(gas)
    }

    fn call_context(
        &self,
        gas_price: U256,
        origin: H160,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> CallContext<'_> {
        CallContext {
            state: self,
            gas_price,
            origin,
            chain_id,
            current_block,
        }
    }

    fn executor<'a>(
        &'a self,
        context: &'a CallContext<'a>,
        gas_limit: u64,
    ) -> StackExecutor<MemoryStackState<CallContext<'a>>, ()> {
        let stack_state_metadata = StackSubstateMetadata::new(gas_limit, &CONFIG);
        let stack_state = MemoryStackState::new(stack_state_metadata, context);
        StackExecutor::new_with_precompiles(stack_state, &CONFIG, &())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_contract(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: U256,
        chain_id: u64,
        current_block: BlockHeader,
        _print_enabled: bool,
        _tracing: bool,
    ) -> Result<Vec<u8>> {
        let context = self.call_context(U256::zero(), from_addr, chain_id, current_block);

        let mut executor = self.executor(&context, u64::MAX);

        let (reason, data) = if let Some(to_addr) = to_addr {
            executor.transact_call(from_addr, to_addr, amount, data, u64::MAX, vec![])
        } else {
            executor.transact_create(from_addr, amount, data, u64::MAX, vec![])
        };

        match reason {
            ExitReason::Succeed(_) | ExitReason::Revert(_) | ExitReason::Error(_) => Ok(data),
            ExitReason::Fatal(e) => Err(anyhow!("EVM fatal error: {e:?}")),
        }
    }
}

pub struct CallContext<'a> {
    state: &'a State,
    gas_price: U256,
    origin: H160,
    chain_id: u64,
    current_block: BlockHeader,
}

impl<'a> evm::backend::Backend for CallContext<'a> {
    fn gas_price(&self) -> U256 {
        self.gas_price
    }

    fn origin(&self) -> H160 {
        self.origin
    }

    fn block_hash(&self, _: U256) -> H256 {
        // TODO: Get the hash of one of the 256 most recent blocks.
        H256::zero()
    }

    fn block_number(&self) -> U256 {
        self.current_block.view.into()
    }

    fn block_coinbase(&self) -> H160 {
        // TODO: Return something here, probably the proposer of the current block.
        H160::zero()
    }

    fn block_timestamp(&self) -> U256 {
        self.current_block
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
            .into()
    }

    fn block_difficulty(&self) -> U256 {
        0.into()
    }

    fn block_randomness(&self) -> Option<H256> {
        None
    }

    fn block_gas_limit(&self) -> U256 {
        0.into()
    }

    fn block_base_fee_per_gas(&self) -> U256 {
        0.into()
    }

    fn chain_id(&self) -> U256 {
        self.chain_id.into()
    }

    fn exists(&self, address: H160) -> bool {
        self.state.has_account(address)
    }

    fn basic(&self, address: H160) -> Basic {
        let nonce = self.state.must_get_account(address).nonce;
        // For these accounts, we hardcode the balance we return to the EVM engine as zero. Otherwise, we have an
        // infinite recursion because getting the native balance of any account requires this method to be called for
        // these two 'special' accounts.
        let is_special_account = address.is_zero() || address == contract_addr::NATIVE_TOKEN;
        Basic {
            balance: if is_special_account {
                0.into()
            } else {
                self.state.get_native_balance(address, false).unwrap()
            },
            nonce: nonce.into(),
        }
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.state.must_get_account(address).code
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.state.must_get_account_storage(address, index)
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }
}
