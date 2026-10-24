use alloy::primitives::Address;
use anyhow::{Result, anyhow};
use revm::{
    context::result::{ExecutionResult, Output, ResultAndState},
    context_interface::TransactionType,
};

use super::{BaseFeeAndNonceCheck, ExecType, ExtraOpts};
use crate::{crypto::Hash, inspector, message::BlockHeader, state::State};

impl State {
    pub(crate) fn force_deploy_contract_evm(
        &mut self,
        creation_bytecode: Vec<u8>,
        override_address: Option<Address>,
        amount: u128,
    ) -> Result<Address> {
        let current_block = BlockHeader::genesis(Hash::ZERO);
        let deployer_nonce = self.get_account(Address::ZERO)?.nonce;
        let (ResultAndState { result, mut state }, ..) = self.apply_transaction_evm(
            Address::ZERO,
            None,
            0,
            None,
            self.block_gas_limit,
            amount,
            creation_bytecode,
            Some(deployer_nonce),
            None,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            ExtraOpts {
                disable_eip3607: false,
                exec_type: ExecType::Transact,
                tx_type: TransactionType::Legacy,
            },
        )?;

        match result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(addr)),
                ..
            } => {
                let addr = if let Some(override_address) = override_address {
                    let override_address = Address::from(override_address.0);
                    let account = state
                        .remove(&addr)
                        .ok_or_else(|| anyhow!("deployment did not change the contract account"))?;
                    state.insert(override_address, account);
                    override_address
                } else {
                    addr
                };

                self.apply_delta_evm(&state, current_block.number)?;
                Ok(addr)
            }
            ExecutionResult::Success { .. } => Err(anyhow!("deployment did not create a contract")),
            ExecutionResult::Revert { .. } => Err(anyhow!("deployment reverted")),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("deployment halted: {reason:?}")),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn call_contract(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: u128,
        current_block: BlockHeader,
    ) -> Result<ExecutionResult> {
        let caller_nonce = self.get_account(from_addr)?.nonce;
        let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            0,
            None,
            self.block_gas_limit,
            amount,
            data,
            Some(caller_nonce),
            None,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            ExtraOpts {
                disable_eip3607: true,
                exec_type: ExecType::Call,
                tx_type: TransactionType::Legacy,
            },
        )?;

        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_contract_apply(
        &mut self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: u128,
        current_block: BlockHeader,
    ) -> Result<ExecutionResult> {
        let caller_nonce = self.get_account(from_addr)?.nonce;
        let (ResultAndState { result, state }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            0,
            None,
            self.block_gas_limit,
            amount,
            data,
            Some(caller_nonce),
            None,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            ExtraOpts {
                disable_eip3607: false,
                exec_type: ExecType::Transact,
                tx_type: TransactionType::Legacy,
            },
        )?;
        self.apply_delta_evm(&state, current_block.number)?;

        Ok(result)
    }
}
