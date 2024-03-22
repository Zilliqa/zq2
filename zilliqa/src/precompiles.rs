use crate::state::State;

use revm::{
    primitives::{Bytes, PrecompileResult},
    ContextStatefulPrecompile, InnerEvmContext,
};
pub(crate) struct ERC20Precompile;

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
