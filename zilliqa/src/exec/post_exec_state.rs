mod failure;

use std::collections::HashMap;

use alloy::primitives::Address;
use anyhow::{Result, anyhow};
use eth_trie::{EthTrie, Trie};
use revm::{
    Inspector,
    context::result::{ExecutionResult, ResultAndState},
    handler::EvmTr,
    primitives::{B256, KECCAK_EMPTY},
    state::EvmState,
};
use revm_context::ContextTr;
use tracing::trace;

use super::{ExecType, ExtraOpts, PendingAccount, PendingState, ScillaResult, StorageValue};
use crate::{
    blocked_recipients::BLOCKED_NONCE_FLOOR,
    cfg::Fork,
    evm::{ZQ2Evm, ZQ2EvmContext},
    inspector::ScillaInspector,
    precompiles::{PENALTY_ADDRESS, SCILLA_CALL_ADDRESS},
    scilla::storage_key,
    state::{Account, Code, State},
    trie_storage::TrieStorage,
};

impl State {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finalize_evm_outcome_legacy<I: Inspector<ZQ2EvmContext> + ScillaInspector>(
        &self,
        evm: &mut ZQ2Evm<I>,
        result_and_state: ResultAndState,
        fork: &Fork,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u128,
        max_priority_fee_per_gas: Option<u128>,
        enable_inspector: bool,
        extra_opts: ExtraOpts,
    ) -> Result<(ResultAndState, HashMap<Address, PendingAccount>)> {
        let ResultAndState { result, state } = result_and_state;

        let mut state: EvmState = state
            .into_iter()
            .filter(|(addr, _)| *addr != SCILLA_CALL_ADDRESS && *addr != PENALTY_ADDRESS)
            .collect();

        if fork.remove_scilla_contracts_from_evm_delta {
            let mut scilla_contracts = Vec::new();
            for address in state.keys() {
                if self.get_account(*address)?.code.is_scilla() {
                    scilla_contracts.push(*address);
                }
            }
            for address in scilla_contracts {
                state.remove(&address);
            }
        }

        let result_and_state = ResultAndState { result, state };

        if enable_inspector {
            replay_touched_addresses(evm);
        }
        let ctx_with_handler = evm.ctx();

        let force_fail =
            failure::should_force_fail(&ctx_with_handler.chain, fork, extra_opts.exec_type);

        let finalized_state = ctx_with_handler.db_mut().finalize();

        let deltas_overlap = fork
            .allow_scilla_call_precompile_to_be_called_from_addresses
            .is_empty()
            && fork.tighten_precompile_rules
            && extra_opts.exec_type == ExecType::Transact
            && failure::deltas_overlap(
                &result_and_state.state,
                &finalized_state,
                fork.only_mutated_accounts_update_state,
            );

        let blocked_recipient = self.blocked_recipient(fork, to_addr, extra_opts.exec_type)?;

        if force_fail || deltas_overlap || blocked_recipient {
            let result_and_state = failure::failed(
                self,
                fork,
                from_addr,
                gas_price,
                max_priority_fee_per_gas,
                result_and_state,
            )?;
            return Ok((result_and_state, HashMap::new()));
        }

        Ok((result_and_state, finalized_state))
    }

    fn blocked_recipient(
        &self,
        fork: &Fork,
        to_addr: Option<Address>,
        exec_type: ExecType,
    ) -> Result<bool> {
        Ok((fork.blocked_recipients_start_height != 0
            || fork.blocked_recipients_start_height_v2 != 0
            || fork.blocked_recipients_start_height_v3 != 0
            || fork.blocked_recipients_start_height_v4 != 0)
            && exec_type == ExecType::Transact
            && match to_addr {
                Some(to) => self.get_account(to)?.nonce == BLOCKED_NONCE_FLOOR,
                None => false,
            })
    }

    pub(crate) fn commit_evm_tx(
        &mut self,
        result: &ExecutionResult,
        state: &EvmState,
        scilla_state: &HashMap<Address, PendingAccount>,
        current_block_number: u64,
    ) -> Result<()> {
        self.apply_delta_evm(state, current_block_number)?;
        let apply_scilla_delta_when_evm_succeeded = self
            .forks
            .get(current_block_number)
            .apply_scilla_delta_when_evm_succeeded;

        if apply_scilla_delta_when_evm_succeeded {
            if let ExecutionResult::Success { .. } = result {
                self.apply_delta_scilla(scilla_state, Some(state), current_block_number)?;
            }
        } else {
            self.apply_delta_scilla(scilla_state, Some(state), current_block_number)?;
        }
        Ok(())
    }

    pub(super) fn commit_scilla_tx(
        &mut self,
        result: &ScillaResult,
        state: &HashMap<Address, PendingAccount>,
        from_addr: Address,
        current_block_number: u64,
    ) -> Result<()> {
        let update_state_only_if_transaction_succeeds = self
            .forks
            .get(current_block_number)
            .apply_state_changes_only_if_transaction_succeeds;

        if !update_state_only_if_transaction_succeeds || result.success {
            self.apply_delta_scilla(state, None, current_block_number)?;
        } else {
            let from_account = state
                .get(&from_addr)
                .ok_or(anyhow!("from account not found"))?;

            let mut storage = self.get_account_trie(from_addr)?;

            let account = Account {
                nonce: from_account.account.nonce,
                balance: from_account.account.balance,
                code: from_account.account.code.clone(),
                storage_root: storage.root_hash()?,
            };

            self.save_account(from_addr, account)?;
        }
        Ok(())
    }

    pub(crate) fn apply_delta_scilla(
        &mut self,
        state: &HashMap<Address, PendingAccount>,
        evm_state: Option<&EvmState>,
        current_block_number: u64,
    ) -> Result<()> {
        let fork = self.forks.get(current_block_number);
        let only_mutated_accounts_update_state = fork.only_mutated_accounts_update_state;
        let scilla_delta_maps_are_applied_correctly = fork.scilla_delta_maps_are_applied_correctly;
        let dont_overwrite_evm_accounts_from_stale_scilla_state =
            fork.dont_overwrite_evm_accounts_from_stale_scilla_state;
        for (&address, account) in state {
            if only_mutated_accounts_update_state && !account.touched {
                continue;
            }
            if dont_overwrite_evm_accounts_from_stale_scilla_state
                && let Some(evm) = evm_state
                && evm.contains_key(&address)
            {
                continue;
            }

            assert!(!account.from_evm);

            let mut storage = self.get_account_trie(address)?;

            for (var, value) in &account.storage {
                apply_storage_value(
                    scilla_delta_maps_are_applied_correctly,
                    &mut storage,
                    var,
                    value,
                    &mut vec![],
                )?;
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

    pub fn apply_delta_evm(&mut self, state: &EvmState, current_block_number: u64) -> Result<()> {
        let only_mutated_accounts_update_state = self
            .forks
            .get(current_block_number)
            .only_mutated_accounts_update_state;
        for (&address, account) in state {
            if only_mutated_accounts_update_state && !account.is_touched() {
                continue;
            }

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

            let mut code = if account.info.code_hash == KECCAK_EMPTY {
                Code::Evm(vec![])
            } else {
                Code::Evm(
                    account
                        .info
                        .code
                        .as_ref()
                        .expect("code_by_hash is not used")
                        .original_bytes()
                        .to_vec(),
                )
            };

            let fork = self.forks.get(current_block_number).clone();
            if fork.scilla_fix_contract_code_removal_on_evm_tx {
                let mut pending_state = PendingState::new(self.try_clone()?, fork);
                let zq2_account = pending_state.load_account(address)?;
                if zq2_account.account.code.is_scilla() {
                    code = zq2_account.account.code.clone()
                }
            }

            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.try_into()?,
                code,
                storage_root: storage.root_hash()?,
            };
            trace!(?address, ?account, "update account");
            self.save_account(address, account)?;
        }

        Ok(())
    }
}

fn replay_touched_addresses<I: Inspector<ZQ2EvmContext> + ScillaInspector>(evm: &mut ZQ2Evm<I>) {
    let touched_address = &evm.0.ctx.chain.touched_address_inspector.touched;
    let inspector = &mut evm.0.inspector;
    for touched_address in touched_address.iter() {
        ScillaInspector::call(inspector, *touched_address, *touched_address, 0, 0);
    }
}

pub(super) fn apply_storage_value(
    scilla_delta_maps_are_applied_correctly: bool,
    storage: &mut EthTrie<TrieStorage>,
    var: &str,
    value: &StorageValue,
    indices: &mut Vec<Vec<u8>>,
) -> Result<()> {
    match value {
        StorageValue::Map { map, complete } => {
            if *complete {
                storage.remove_by_prefix(&storage_key(var, indices))?;
            }

            indices.push(vec![]);
            for (k, v) in map {
                indices.last_mut().unwrap().clone_from(k);
                apply_storage_value(
                    scilla_delta_maps_are_applied_correctly,
                    storage,
                    var,
                    v,
                    indices,
                )?;
            }
            if scilla_delta_maps_are_applied_correctly {
                indices.pop();
            }
        }
        StorageValue::Value(Some(value)) => {
            let key = storage_key(var, indices);
            storage.insert(&key, value)?;
        }
        StorageValue::Value(None) => {
            let key = storage_key(var, indices);
            storage.remove_by_prefix(&key)?;
        }
    }
    Ok(())
}
