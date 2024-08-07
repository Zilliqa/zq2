mod erc20;
mod pop_verify;
mod scilla_read;

use std::sync::Arc;

use alloy::primitives::Address;
use erc20::ERC20Precompile;
use pop_verify::PopVerify;
use revm::ContextPrecompile;
use scilla_read::ScillaRead;

use crate::state::State;

pub fn get_custom_precompiles<'a>() -> Vec<(Address, ContextPrecompile<&'a State>)> {
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
    ]
}
