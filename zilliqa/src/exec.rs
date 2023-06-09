//! Manages execution of transactions on state.

use std::{borrow::Cow, collections::HashSet, time::SystemTime};

use evm_ds::call_context::CallContext;

use anyhow::{anyhow, Result};
use ethabi::Token;
use evm_ds::evm::{
    backend::{Apply, Backend, Basic},
    executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata},
    tracing::EventListener,
    Config, CreateScheme, ExitReason, Runtime,
};
use evm_ds::cps_executor::{CpsExecutor};
use primitive_types::{H160, H256, U256};
use tracing::info;

use crate::{
    contracts,
    message::BlockHeader,
    state::{Address, Log, State, Transaction},
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

//pub struct CallContext<'a> {
//    state: &'a State,
//    gas_price: U256,
//    origin: H160,
//    chain_id: u64,
//    current_block: BlockHeader,
//}

//const CONFIG: Config = Config::shanghai();
const CONFIG: Config = Config::london();

/// Data returned after applying a [Transaction] to [State].
pub struct TransactionApplyResult {
    /// Whether the transaction succeeded and the resulting state changes were persisted.
    pub success: bool,
    /// If the transaction was a contract creation, the address of the resulting contract.
    pub contract_address: Option<Address>,
    /// The logs emitted by the transaction execution.
    pub logs: Vec<Log>,
}

impl TransactionApplyResult {
    fn failed() -> TransactionApplyResult {
        TransactionApplyResult {
            success: false,
            contract_address: None,
            logs: vec![],
        }
    }
}

impl State {
    //fn call_context(
    //    &self,
    //    gas_price: U256,
    //    origin: H160,
    //    chain_id: u64,
    //    current_block: BlockHeader,
    //) -> CallContext<'_> {
    //    CallContext {
    //        state: self,
    //        gas_price,
    //        origin,
    //        chain_id,
    //        current_block,
    //    }
    //}

    /*
    fn executor<'a>(
        &'a self,
        context: &'a CallContext,
        gas_limit: u64,
    ) -> StackExecutor<MemoryStackState<CallContext>, ()> {
        let stack_state_metadata = StackSubstateMetadata::new(gas_limit, &CONFIG);
        let stack_state = MemoryStackState::new(stack_state_metadata, context);
        StackExecutor::new_with_precompiles(stack_state, &CONFIG, &())
    }
    */

    /// Deploy a contract at a fixed address. Used for system contracts which exist at well known addresses.
    pub fn deploy_fixed_contract(&mut self, address: Address, code: Vec<u8>) {
        self.get_account_mut(address).code = code;
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_transaction_inner(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        gas_price: u128,
        gas_limit: u64,
        amount: u128,
        payload: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<TransactionApplyResult> {
        //let context = self.call_context(gas_price.into(), from_addr.0, chain_id, current_block);
        let context = CallContext::new();

        let runtime = Runtime::new(payload, data.clone(), context, &config);
        let state = MemoryStackState::new(metadata, &backend);

        //let mut executor = self.executor(&context, gas_limit);
        let mut executor = CpsExecutor::new_with_precompiles(state, &config, &precompiles, enable_cps);

        let (exit_reason, contract_address) = if to_addr == Address::DEPLOY_CONTRACT {
            let address = executor.create_address(CreateScheme::Legacy {
                caller: from_addr.0,
            });
            let (exit_reason, _) =
                executor.transact_create(from_addr.0, amount.into(), payload, gas_limit, vec![]);
            (exit_reason, Some(address))
        } else {
            let (exit_reason, _) = executor.transact_call(
                from_addr.0,
                to_addr.0,
                amount.into(),
                payload,
                gas_limit,
                vec![],
            );
            (exit_reason, None)
        };

        match exit_reason {
            ExitReason::Succeed(_) => {}
            ExitReason::Error(_) | ExitReason::Revert(_) => {
                return Ok(TransactionApplyResult::failed());
            }
            ExitReason::Fatal(e) => {
                return Err(anyhow!("EVM fatal error: {e:?}"));
            }
        }

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
        let mut logs: Vec<_> = logs
            .into_iter()
            .map(|log| Log {
                address: Address(log.address),
                topics: log.topics,
                data: log.data,
            })
            .collect();

        self.apply_delta(&mut logs, to_addr, applys)?;

        info!("transaction processed");

        Ok(TransactionApplyResult {
            success: true,
            contract_address: contract_address.map(Address),
            logs,
        })
    }

    /// Apply a transaction to the account state. If the transaction is a contract creation, the created contract's
    /// address will be added to the transaction.
    pub fn apply_transaction(
        &mut self,
        txn: Transaction,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<TransactionApplyResult> {
        self.apply_transaction_inner(
            txn.addr_from(),
            txn.to_addr,
            txn.gas_price,
            100000000000000, // Workaround until gas is implemented.
            txn.amount,
            txn.payload,
            chain_id,
            current_block,
        )
    }

    fn apply_delta(
        &mut self,
        logs: &mut Vec<Log>,
        to_addr: Address,
        applys: impl IntoIterator<Item = Apply<impl IntoIterator<Item = (H256, H256)>>>,
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
                    let address = Address(address);

                    // If the `to_addr` was `Address::NATIVE_TOKEN`, then this transaction was a call to the native
                    // token contract. Avoid applying further updates to the native balance in this case, which would
                    // result in an endless recursion.
                    // FIXME: This makes it impossible to charge gas for calls to `Address::NATIVE_TOKEN`.
                    // FIXME: We ignore the change if the balance is zero. According to the SputnikVM example code,
                    // this is the intended implementation. However, that might mean it is impossible to tell the
                    // difference between an account that has been fully drained and an account whose balance has not
                    // been changed. We should investigate if this is really an issue.
                    if to_addr != Address::NATIVE_TOKEN && !basic.balance.is_zero() {
                        self.set_native_balance(logs, address, basic.balance)?;
                    }

                    let account = self.get_account_mut(address);

                    if let Some(code) = code {
                        account.code = code;
                    }

                    account.nonce = basic.nonce.as_u64();

                    if reset_storage {
                        account.storage.clear();
                    }

                    for (index, value) in storage {
                        if value.is_zero() {
                            account.storage.remove(&index);
                        } else {
                            account.storage.insert(index, value);
                        }
                    }
                }
                Apply::Delete { address } => {
                    let account = self.get_account_mut(Address(address));
                    *account = Default::default();
                }
            }
        }
        hellow();

        Ok(())
    }

    pub fn get_native_balance(&self, address: Address) -> Result<U256> {
        let data = contracts::native_token::BALANCE_OF
            .encode_input(&[Token::Address(address.0)])
            .unwrap();

        let balance = self.call_contract(
            Address::DEPLOY_CONTRACT,
            Address::NATIVE_TOKEN,
            data,
            // The chain ID and current block are not accessed when the native balance is read, so we just pass in some
            // dummy values.
            0,
            BlockHeader::genesis(),
        )?;
        let balance = U256::from_big_endian(&balance);

        Ok(balance)
    }

    pub fn set_native_balance(
        &mut self,
        logs: &mut Vec<Log>,
        address: Address,
        amount: U256,
    ) -> Result<()> {
        let data = contracts::native_token::SET_BALANCE
            .encode_input(&[Token::Address(address.0), Token::Uint(amount)])
            .unwrap();

        let result = self.apply_transaction_inner(
            Address::DEPLOY_CONTRACT,
            Address::NATIVE_TOKEN,
            u128::MAX,
            u64::MAX,
            0,
            data,
            // The chain ID and current block are not accessed when the native balance is updated, so we just pass in
            // some dummy values.
            0,
            BlockHeader::genesis(),
        )?;

        if !result.success {
            return Err(anyhow!(
                "setting native balance failed, this should never happen"
            ));
        }
        logs.extend_from_slice(&result.logs);

        Ok(())
    }

    pub fn call_contract(
        &self,
        caller: Address,
        contract: Address,
        data: Vec<u8>,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<Vec<u8>> {
        let context = self.call_context(U256::zero(), caller.0, chain_id, current_block);

        if context.code(contract.0).is_empty() {
            return Ok(vec![]);
        }

        let mut executor = self.executor(&context, u64::MAX);

        let (reason, data) =
            executor.transact_call(caller.0, contract.0, 0.into(), data, u64::MAX, vec![]);
        match reason {
            ExitReason::Succeed(_) | ExitReason::Revert(_) | ExitReason::Error(_) => Ok(data),
            ExitReason::Fatal(e) => Err(anyhow!("EVM fatal error: {e:?}")),
        }
    }
}

//impl<'a> Backend for CallContext<'a> {
//    fn gas_price(&self) -> U256 {
//        self.gas_price
//    }
//
//    fn origin(&self) -> H160 {
//        self.origin
//    }
//
//    fn block_hash(&self, _: U256) -> H256 {
//        // TODO: Get the hash of one of the 256 most recent blocks.
//        H256::zero()
//    }
//
//    fn block_number(&self) -> U256 {
//        self.current_block.view.into()
//    }
//
//    fn block_coinbase(&self) -> H160 {
//        // TODO: Return something here, probably the proposer of the current block.
//        H160::zero()
//    }
//
//    fn block_timestamp(&self) -> U256 {
//        self.current_block
//            .timestamp
//            .duration_since(SystemTime::UNIX_EPOCH)
//            .map(|duration| duration.as_secs())
//            .unwrap_or_default()
//            .into()
//    }
//
//    fn block_difficulty(&self) -> U256 {
//        0.into()
//    }
//
//    fn block_randomness(&self) -> Option<H256> {
//        None
//    }
//
//    fn block_gas_limit(&self) -> U256 {
//        0.into()
//    }
//
//    fn block_base_fee_per_gas(&self) -> U256 {
//        0.into()
//    }
//
//    fn chain_id(&self) -> U256 {
//        self.chain_id.into()
//    }
//
//    fn exists(&self, address: H160) -> bool {
//        // Ethereum charges extra gas for `CALL`s or `SELFDESTRUCT`s which create new accounts, to discourage the
//        // creation of many addresses and the resulting increase in state size. We can tell if an account exists in our
//        // state by checking whether the response from `State::get_account` is borrowed.
//        matches!(self.state.get_account(Address(address)), Cow::Borrowed(_))
//    }
//
//    fn basic(&self, address: H160) -> Basic {
//        let nonce = self.state.get_account(Address(address)).nonce;
//        // For these accounts, we hardcode the balance we return to the EVM engine as zero. Otherwise, we have an
//        // infinite recursion because getting the native balance of any account requires this method to be called for
//        // these two 'special' accounts.
//        let is_special_account =
//            address == Address::DEPLOY_CONTRACT.0 || address == Address::NATIVE_TOKEN.0;
//        Basic {
//            balance: if is_special_account {
//                0.into()
//            } else {
//                self.state.get_native_balance(Address(address)).unwrap()
//            },
//            nonce: nonce.into(),
//        }
//    }
//
//    fn code(&self, address: H160) -> Vec<u8> {
//        self.state.get_account(Address(address)).code.to_owned()
//    }
//
//    fn storage(&self, address: H160, index: H256) -> H256 {
//        self.state
//            .get_account(Address(address))
//            .storage
//            .get(&index)
//            .copied()
//            .unwrap_or_default()
//    }
//
//    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
//        Some(self.storage(address, index))
//    }
//}
