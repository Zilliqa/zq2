use alloy::primitives::Address;
use anyhow::{Context, Result, anyhow};
use jsonrpsee::types::ErrorObjectOwned;
use revm::{
    context::result::{ExecutionResult, HaltReason, ResultAndState},
    context_interface::transaction::{AccessList, SignedAuthorization},
};
use tracing::debug;

use super::{BaseFeeAndNonceCheck, ExtraOpts};
use crate::{
    constants, error::ensure_success, inspector, message::BlockHeader, state::State,
    transaction::EvmGas,
};

impl State {
    fn max_gas_for_caller(
        &self,
        caller: Address,
        tx_value: u128,
        gas_price: u128,
        requested_gas_limit: Option<EvmGas>,
    ) -> Result<EvmGas> {
        let mut gas = self.block_gas_limit;

        if let Some(requested_gas_limit) = requested_gas_limit {
            gas = gas.min(requested_gas_limit);
        }

        if gas_price == 0 {
            return Ok(gas);
        }

        let balance = self.get_account(caller)?.balance;
        let balance = balance.checked_sub(tx_value).ok_or_else(|| {
            anyhow!("caller has insufficient funds - has: {balance}, needs: {tx_value}")
        })?;
        let balance = balance.checked_div(gas_price).context("gas_price != 0")?;
        let max_gas = EvmGas(balance.try_into()?);
        gas = gas.min(max_gas);
        Ok(gas)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        current_block: BlockHeader,
        gas: Option<EvmGas>,
        gas_price: Option<u128>,
        max_priority_fee_per_gas: Option<u128>,
        value: u128,
        access_list: Option<AccessList>,
        authorization_list: Option<Vec<SignedAuthorization>>,
        extra_opts: ExtraOpts,
    ) -> Result<u64> {
        let gas_price = gas_price.unwrap_or(self.gas_price);
        let caller_nonce = self.get_account(from_addr)?.nonce;

        let is_simple_transfer = if data.is_empty()
            && let Some(dest_addr) = to_addr
        {
            self.get_account(dest_addr)?.code.is_eoa()
        } else {
            false
        };

        if is_simple_transfer {
            let gas = gas.unwrap_or(constants::EVM_MIN_GAS_UNITS);
            if let Ok(result) = self.apply_transaction_evm(
                from_addr,
                to_addr,
                gas_price,
                max_priority_fee_per_gas,
                gas,
                value,
                data.clone(),
                Some(caller_nonce),
                access_list.clone(),
                authorization_list.clone(),
                current_block,
                inspector::noop(),
                false,
                BaseFeeAndNonceCheck::Ignore,
                extra_opts,
            ) && result.0.result.is_success()
            {
                return Ok(constants::EVM_MIN_GAS_UNITS.0);
            }
        }

        let mut max = self.max_gas_for_caller(from_addr, value, gas_price, gas)?.0;

        let upper_bound = max;

        let mut min = self.estimate_gas_inner(
            from_addr,
            to_addr,
            data.clone(),
            current_block,
            EvmGas(upper_bound),
            gas_price,
            max_priority_fee_per_gas,
            value,
            access_list.clone(),
            authorization_list.clone(),
            extra_opts,
        )?;

        const MINIMUM_PERCENT_RATIO: u64 = 3;

        while min < max {
            let break_cond = (max - min) <= (max * MINIMUM_PERCENT_RATIO) / 100;
            if break_cond {
                break;
            }
            let mid = (min + max) / 2;

            let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
                from_addr,
                to_addr,
                gas_price,
                max_priority_fee_per_gas,
                EvmGas(mid),
                value,
                data.clone(),
                Some(caller_nonce),
                access_list.clone(),
                authorization_list.clone(),
                current_block,
                inspector::noop(),
                false,
                BaseFeeAndNonceCheck::Ignore,
                extra_opts,
            )?;

            match result {
                ExecutionResult::Success { .. } => max = mid,
                ExecutionResult::Revert { .. } => min = mid + 1,
                ExecutionResult::Halt { reason, .. } => match reason {
                    HaltReason::OutOfGas(_) | HaltReason::InvalidFEOpcode => min = mid + 1,
                    _ => return Err(anyhow!("halted due to: {reason:?}")),
                },
            }
        }
        debug!("Estimated gas: {}", max);
        Ok(max)
    }
    #[allow(clippy::too_many_arguments)]
    fn estimate_gas_inner(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        current_block: BlockHeader,
        gas: EvmGas,
        gas_price: u128,
        max_priority_fee_per_gas: Option<u128>,
        value: u128,
        access_list: Option<AccessList>,
        authorization_list: Option<Vec<SignedAuthorization>>,
        extra_opts: ExtraOpts,
    ) -> Result<u64> {
        let caller_nonce = self.get_account(from_addr)?.nonce;
        let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            gas_price,
            max_priority_fee_per_gas,
            gas,
            value,
            data.clone(),
            Some(caller_nonce),
            access_list,
            authorization_list,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            extra_opts,
        )?;

        let gas_used = result.tx_gas_used();
        ensure_success(result).map_err(ErrorObjectOwned::from)?;
        Ok(gas_used)
    }
}
