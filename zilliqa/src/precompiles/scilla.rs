mod call;
mod read;
mod types;

use alloy::primitives::Address;
use revm::interpreter::CallInputs;
use revm_precompile::PrecompileHalt;
use tracing::trace;

pub use call::ScillaCall;
pub use read::ScillaRead;

use crate::evm::ZQ2EvmContext;

pub enum PrecompileErrors {
    Error(PrecompileHalt),
    Fatal { msg: String },
}

#[track_caller]
fn oog<T>() -> Result<T, PrecompileErrors> {
    let location = std::panic::Location::caller();
    let msg = "scilla_call out of gas";
    trace!(%location, msg);
    Err(PrecompileErrors::Error(PrecompileHalt::OutOfGas))
}

#[track_caller]
fn err<T>(message: impl Into<String>) -> Result<T, PrecompileErrors> {
    let location = std::panic::Location::caller();
    let message = message.into();
    trace!(%location, message, "scilla_call failed");
    Err(err_inner(message))
}

#[track_caller]
fn err_inner(message: impl Into<String>) -> PrecompileErrors {
    let location = std::panic::Location::caller();
    let message = message.into();
    trace!(%location, message, "scilla_call failed");
    PrecompileErrors::Error(PrecompileHalt::other(message))
}

#[track_caller]
fn fatal<T>(message: &'static str) -> Result<T, PrecompileErrors> {
    let location = std::panic::Location::caller();
    trace!(%location, message, "scilla_call failed");
    Err(PrecompileErrors::Fatal {
        msg: message.to_string(),
    })
}

const BASE_COST: u64 = 15;
const PER_BYTE_COST: u64 = 3;

fn interop_disabled_for_target(ctx: &mut ZQ2EvmContext, inputs: &CallInputs) -> bool {
    if ctx
        .chain
        .fork
        .disable_permanently_scilla_precompiles_v1
        .is_empty()
    {
        return false;
    }
    let input = inputs.input.bytes(ctx);
    input.len() >= 32
        && ctx
            .chain
            .fork
            .disable_permanently_scilla_precompiles_v1
            .contains(&Address::from_slice(&input[12..32]))
}
