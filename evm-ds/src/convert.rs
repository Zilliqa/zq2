use crate::evm::ExitReason;
use crate::protos::evm as EvmProto;
use crate::protos::evm::*;

impl From<evm::ExitReason> for EvmProto::ExitReasonCps {
    fn from(exit_reason: evm::ExitReason) -> Self {
        match exit_reason {
            ExitReason::Succeed(s) => ExitReasonCps::Succeed(s),
            ExitReason::Error(e) => ExitReasonCps::Error(e),
            ExitReason::Revert(r) => ExitReasonCps::Revert(r),
            ExitReason::Fatal(f) => ExitReasonCps::Fatal(f),
        }
    }
}
