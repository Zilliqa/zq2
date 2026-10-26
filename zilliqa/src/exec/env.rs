use std::{collections::HashMap, sync::Arc};

use alloy::primitives::{Address, U256};
use parking_lot::RwLock;
use revm::{context_interface::TransactionType, primitives::hardfork::SpecId, state::EvmState};

use super::PendingAccount;
use crate::{
    cfg::Fork,
    inspector::TouchedAddressInspector,
    precompiles::{SCILLA_CALL_ADDRESS, ViewHistory},
};

#[derive(Clone, Copy, PartialEq)]
pub enum ExecType {
    Call,
    Estimate,
    Transact,
}

#[derive(Clone, Copy)]
pub struct ExtraOpts {
    pub(crate) disable_eip3607: bool,
    pub(crate) exec_type: ExecType,
    pub(crate) tx_type: TransactionType,
}

pub struct ExternalContext {
    pub touched_address_inspector: TouchedAddressInspector,
    pub fork: Fork,
    pub enforce_transaction_failure: bool,
    pub callers: Vec<Address>,
    pub has_evm_failed: bool,
    pub has_called_scilla_precompile: bool,
    pub finalized_view: u64,
    pub view_history: Arc<RwLock<ViewHistory>>,
    pub spec_id: SpecId,
    pub scilla_snapshots: Vec<PendingAccount>,
}

impl ExternalContext {
    fn scilla_snapshot(&self, id: U256) -> Option<&PendingAccount> {
        self.scilla_snapshots
            .get(usize::try_from(id).ok()?.checked_sub(1)?)
    }

    pub fn pinned_scilla_state(&self, state: &EvmState) -> HashMap<Address, PendingAccount> {
        state
            .get(&SCILLA_CALL_ADDRESS)
            .into_iter()
            .flat_map(|account| &account.storage)
            .filter_map(|(key, slot)| {
                Some((
                    Address::from_word((*key).into()),
                    self.scilla_snapshot(slot.present_value)?.clone(),
                ))
            })
            .collect()
    }

    pub fn pinned_scilla_account(
        &self,
        state: &EvmState,
        address: Address,
    ) -> Option<&PendingAccount> {
        self.scilla_snapshot(
            state
                .get(&SCILLA_CALL_ADDRESS)?
                .storage
                .get(&U256::from_be_slice(address.as_slice()))?
                .present_value,
        )
    }
}

pub enum BaseFeeAndNonceCheck {
    Validate,
    ValidateExceptBaseFee,
    Ignore,
}
