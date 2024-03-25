use crate::state::State;
use std::sync::Arc;

use revm::{
    primitives::{Address, Bytes, PrecompileResult},
    ContextPrecompile, ContextStatefulPrecompile, InnerEvmContext,
};
pub(crate) struct ERC20Precompile;

pub(crate) fn get_custom_precompiles<'a>() -> Vec<(Address, ContextPrecompile<&'a State>)> {
    vec![(
        Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL"),
        ContextPrecompile::ContextStateful(Arc::new(ERC20Precompile)),
    )]
}

impl ContextStatefulPrecompile<&State> for ERC20Precompile {
    fn call(
        &self,
        _input: &Bytes,
        _gas_price: u64,
        _context: &mut InnerEvmContext<&State>,
    ) -> PrecompileResult {
        Ok((0, Bytes::new()))
    }
}
