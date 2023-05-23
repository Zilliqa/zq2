//! Manages execution of transactions on state.

use std::{borrow::Cow, time::SystemTime};

use anyhow::{anyhow, Result};
use evm::{
    backend::{Apply, Backend, Basic},
    executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata},
    Capture, Config, Context, CreateScheme, ExitReason, Handler,
};
use primitive_types::{H160, H256, U256};
use tracing::info;

use crate::{
    message::BlockHeader,
    state::{Address, Log, State, Transaction},
};

pub struct CallContext<'a> {
    state: &'a State,
    gas_price: U256,
    origin: H160,
    chain_id: u64,
    current_block: BlockHeader,
}

const CONFIG: Config = Config::london();

impl State {
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

    /// Apply a transaction to the account state. If the transaction is a contract creation, the created contract's
    /// address will be added to the transaction.
    pub fn apply_transaction(
        &mut self,
        txn: Transaction,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<(Option<Address>, Vec<Log>)> {
        let context = self.call_context(
            txn.gas_price.into(),
            txn.from_addr.0,
            chain_id,
            current_block,
        );
        let mut executor = self.executor(&context, txn.gas_limit);

        let contract_address = if txn.to_addr == Address::DEPLOY_CONTRACT {
            let create = executor.create(
                txn.from_addr.0,
                CreateScheme::Legacy {
                    caller: txn.from_addr.0,
                },
                U256::zero(),
                txn.payload.clone(),
                Some(txn.gas_limit),
            );
            // TODO(#80): Do something with the `ExitReason` and data.
            let (_, address, _) = match create {
                Capture::Exit(e) => e,
                Capture::Trap(i) => match i {},
            };
            address
        } else {
            let context = Context {
                address: txn.to_addr.0,
                caller: txn.from_addr.0,
                apparent_value: U256::zero(),
            };
            let call = executor.call(
                txn.to_addr.0,
                None,
                txn.payload.clone(),
                None,
                false,
                context,
            );
            // TODO(#80): Do something with the `ExitReason` and data.
            let (_, _) = match call {
                Capture::Exit(e) => e,
                Capture::Trap(i) => match i {},
            };
            None
        };

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
        let logs: Vec<_> = logs.into_iter().collect();

        for apply in applys {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => {
                    let account = self.get_account_mut(Address(address));

                    if let Some(code) = code {
                        account.code = code;
                    }

                    account.nonce = basic.nonce.as_u64();
                    // TODO(#81): Handle changes in `basic.balance`.

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

        let account = self.get_account_mut(txn.from_addr);
        account.nonce += 1;

        info!("transaction processed");

        Ok((
            contract_address.map(Address),
            logs.into_iter()
                .map(|log| Log {
                    address: Address(log.address),
                    topics: log.topics,
                    data: log.data,
                })
                .collect(),
        ))
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

        let context = Context {
            address: contract.0,
            caller: caller.0,
            apparent_value: U256::zero(),
        };
        let call = executor.call(contract.0, None, data, None, false, context);
        let (reason, data) = match call {
            Capture::Exit(e) => e,
            Capture::Trap(i) => match i {},
        };
        match reason {
            ExitReason::Succeed(_) | ExitReason::Revert(_) | ExitReason::Error(_) => Ok(data),
            ExitReason::Fatal(e) => Err(anyhow!("EVM fatal error: {e:?}")),
        }
    }
}

impl<'a> Backend for CallContext<'a> {
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
        // Ethereum charges extra gas for `CALL`s or `SELFDESTRUCT`s which create new accounts, to discourage the
        // creation of many addresses and the resulting increase in state size. We can tell if an account exists in our
        // state by checking whether the response from `State::get_account` is borrowed.
        matches!(self.state.get_account(Address(address)), Cow::Borrowed(_))
    }

    fn basic(&self, address: H160) -> Basic {
        let nonce = self.state.get_account(Address(address)).nonce;
        Basic {
            balance: U256::exp10(10),
            nonce: nonce.into(),
        }
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.state.get_account(Address(address)).code.to_owned()
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.state
            .get_account(Address(address))
            .storage
            .get(&index)
            .copied()
            .unwrap_or_default()
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }
}
