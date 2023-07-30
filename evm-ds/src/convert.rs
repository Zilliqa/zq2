use evm::ExitSucceed;
use crate::evm::ExitReason;
use crate::protos::{Evm as EvmProto, Evm};
use crate::protos::Evm::*;

impl From<evm::ExitReason> for EvmProto::ExitReasonCps {
    fn from(exit_reason: evm::ExitReason) -> Self {
        //let mut result = Self::new();
        match exit_reason {
            ExitReason::Succeed(s) => ExitReasonCps::Succeed(s),
            ExitReason::Error(e) => ExitReasonCps::Error(e),
            ExitReason::Revert(r) => ExitReasonCps::Revert(r),
            ExitReason::Fatal(f) => ExitReasonCps::Fatal(f),
        }
    }
}
