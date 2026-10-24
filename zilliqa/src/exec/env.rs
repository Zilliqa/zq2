use std::sync::Arc;

use alloy::primitives::Address;
use parking_lot::RwLock;
use revm::{context_interface::TransactionType, primitives::hardfork::SpecId};

use crate::{cfg::Fork, inspector::TouchedAddressInspector, precompiles::ViewHistory};

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
}

pub enum BaseFeeAndNonceCheck {
    Validate,
    ValidateExceptBaseFee,
    Ignore,
}
