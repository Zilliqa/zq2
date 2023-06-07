//! Manages execution of transactions on state.

use cita_trie::DB;
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use evm::{
    backend::{Apply, Backend, Basic},
    executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata},
    Config, CreateScheme, ExitReason,
};
use primitive_types::{H160, H256, U256};
use tracing::info;

use crate::{
    message::BlockHeader,
    state::{Address, Log, State, Transaction},
};

pub struct CallContext<'a, D: DB> {
    state: &'a State<D>,
    gas_price: U256,
    origin: H160,
    chain_id: u64,
    current_block: BlockHeader,
}

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

impl<D: DB> State<D> {
    fn call_context(
        &self,
        gas_price: U256,
        origin: H160,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> CallContext<'_, D> {
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
        context: &'a CallContext<'a, D>,
        gas_limit: u64,
    ) -> StackExecutor<MemoryStackState<CallContext<'a, D>>, ()> {
        let stack_state_metadata = StackSubstateMetadata::new(gas_limit, &CONFIG);
        let stack_state = MemoryStackState::new(stack_state_metadata, context);
        StackExecutor::new_with_precompiles(stack_state, &CONFIG, &())
    }

    /// Apply a transaction to the account state. If the transaction is a contract creation, the created contract's
    /// address will be added to the transaction.
    pub fn apply_transaction(
        &mut self,
        mut txn: Transaction,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Result<TransactionApplyResult> {
        // Workaround until gas is implemented.
        txn.gas_limit = 100000000000000;

        let context = self.call_context(
            txn.gas_price.into(),
            txn.addr_from().0,
            chain_id,
            current_block,
        );
        let mut executor = self.executor(&context, txn.gas_limit);

        let (exit_reason, contract_address) = if txn.to_addr == Address::DEPLOY_CONTRACT {
            let address = executor.create_address(CreateScheme::Legacy {
                caller: txn.addr_from().0,
            });
            let (exit_reason, _) = executor.transact_create(
                txn.addr_from().0,
                txn.amount.into(),
                txn.payload.clone(),
                txn.gas_limit,
                vec![],
            );
            (exit_reason, Some(address))
        } else {
            let (exit_reason, _) = executor.transact_call(
                txn.addr_from().0,
                txn.to_addr.0,
                txn.amount.into(),
                txn.payload.clone(),
                txn.gas_limit,
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
                    let account = self.get_account(Address(address));

                    if let Some(code) = code {
                        account.code = code;
                    }

                    account.nonce = basic.nonce.as_u64();
                    // TODO(#81): Handle changes in `basic.balance`.

                    if reset_storage {
                        account.clear_storage();
                    }

                    for (index, value) in storage {
                        if value.is_zero() {
                            account.remove_storage(index);
                        } else {
                            account.set_storage(index, value);
                        }
                    }
                }
                Apply::Delete { address } => {
                    self.delete_account(Address(address));
                }
            }
        }

        info!("transaction processed");

        Ok(TransactionApplyResult {
            success: true,
            contract_address: contract_address.map(Address),
            logs: logs
                .into_iter()
                .map(|log| Log {
                    address: Address(log.address),
                    topics: log.topics,
                    data: log.data,
                })
                .collect(),
        })
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

impl<'a, D: DB> Backend for CallContext<'a, D> {
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
        self.state.has_account(Address(address))
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
        self.state.get_account(Address(address)).get_storage(index)
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }
}
