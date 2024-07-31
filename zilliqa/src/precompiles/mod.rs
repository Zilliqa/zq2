mod erc20;
mod pop_verify;
mod scilla;

use std::sync::Arc;

use alloy::primitives::Address;
use erc20::ERC20Precompile;
use pop_verify::PopVerify;
use revm::ContextPrecompile;
pub use scilla::scilla_call_handle_register;
use scilla::ScillaRead;

use crate::exec::PendingState;

pub fn get_custom_precompiles() -> Vec<(Address, ContextPrecompile<PendingState>)> {
    vec![
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL"),
            ContextPrecompile::ContextStateful(Arc::new(ERC20Precompile)),
        ),
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x80"),
            ContextPrecompile::ContextStateful(Arc::new(PopVerify)),
        ),
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x92"),
            ContextPrecompile::ContextStateful(Arc::new(ScillaRead)),
        ),
        // The "Scilla call" precompile also exists at address `0x5a494c53`. However, it is implemented by overwriting
        // the `revm` call handler, rather than using a conventional precompile. This is because it requires extra
        // information which isn't provided by the precompile interface, such as the external context (where the
        // inspector is kept), the `msg.sender` and the `msg.value`.
    ]
}
