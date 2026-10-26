use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, U256};
use anyhow::{Result, anyhow};
use revm::{
    context::result::{ExecutionResult, ResultAndState},
    state::EvmState,
};

use crate::{
    cfg::Fork,
    exec::{ExecType, ExternalContext, PendingAccount},
    state::State,
};

pub(crate) fn should_force_fail(chain: &ExternalContext, fork: &Fork, exec_type: ExecType) -> bool {
    chain.enforce_transaction_failure
        || (fork.evm_exec_failure_causes_scilla_precompile_to_fail
            && chain.has_evm_failed
            && chain.has_called_scilla_precompile
            && exec_type == ExecType::Transact)
}

pub(crate) fn deltas_overlap(
    evm_state: &EvmState,
    scilla_state: &HashMap<Address, PendingAccount>,
    only_mutated_accounts_update_state: bool,
) -> bool {
    scilla_state.iter().any(|(addr, account)| {
        (!only_mutated_accounts_update_state || account.touched) && evm_state.contains_key(addr)
    })
}

pub(crate) fn failed(
    state: &State,
    fork: &Fork,
    from_addr: Address,
    gas_price: u128,
    max_priority_fee_per_gas: Option<u128>,
    result_and_state: ResultAndState,
) -> Result<ResultAndState> {
    if fork.tighten_precompile_rules {
        charge_gas(
            state,
            fork,
            from_addr,
            gas_price,
            max_priority_fee_per_gas,
            result_and_state,
        )
    } else {
        discard(result_and_state)
    }
}

fn discard(mut result_and_state: ResultAndState) -> Result<ResultAndState> {
    result_and_state.state.clear();
    Ok(ResultAndState {
        result: ExecutionResult::Revert {
            gas: *result_and_state.result.gas(),
            logs: vec![],
            output: Bytes::default(),
        },
        state: result_and_state.state,
    })
}

fn charge_gas(
    state: &State,
    fork: &Fork,
    from_addr: Address,
    gas_price: u128,
    max_priority_fee_per_gas: Option<u128>,
    result_and_state: ResultAndState,
) -> Result<ResultAndState> {
    let effective_gas_price = match if fork.use_max_gas_priority_fee {
        max_priority_fee_per_gas
    } else {
        None
    } {
        Some(priority) => gas_price.min(state.gas_price.saturating_add(priority)),
        None => gas_price,
    };

    let ResultAndState {
        result,
        state: evm_state,
    } = result_and_state;
    let gas_used = result.tx_gas_used();
    let fee = (gas_used as u128).saturating_mul(effective_gas_price);

    let pre = state.get_account(from_addr)?;

    let mut charged_state = EvmState::default();

    let beneficiary = Address::ZERO;
    if beneficiary != from_addr
        && let Some(beneficiary_acct) = evm_state.get(&beneficiary)
    {
        charged_state.insert(beneficiary, beneficiary_acct.clone());
    }

    let mut sender = evm_state
        .get(&from_addr)
        .cloned()
        .ok_or_else(|| anyhow!("sender account missing from execution state"))?;
    sender.info.balance = U256::from(pre.balance.saturating_sub(fee));
    sender.info.nonce = pre.nonce + 1;
    sender.storage.clear();
    sender.mark_touch();
    charged_state.insert(from_addr, sender);

    Ok(ResultAndState {
        result: ExecutionResult::Revert {
            gas: *result.gas(),
            logs: vec![],
            output: Bytes::default(),
        },
        state: charged_state,
    })
}
