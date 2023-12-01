use crate::evm::ExitReason;
use crate::protos::evm_proto::ExitReasonCps;

// Convert from normal evm to cps evm (traps are set seperately)
impl From<evm::ExitReason> for ExitReasonCps {
    fn from(exit_reason: evm::ExitReason) -> Self {
        match exit_reason {
            ExitReason::Succeed(s) => ExitReasonCps::Succeed(s),
            ExitReason::Error(e) => ExitReasonCps::Error(e),
            ExitReason::Revert(r) => ExitReasonCps::Revert(r),
            ExitReason::Fatal(f) => ExitReasonCps::Fatal(f),
        }
    }
}
