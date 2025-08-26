mod bls_verify;
mod pop_verify;
mod scilla;

use std::sync::Arc;

use alloy::primitives::Address;
use revm::context_interface::{Cfg, ContextTr};
use revm::handler::{EthPrecompiles, PrecompileProvider};
use revm::interpreter::{InputsImpl, InterpreterResult};
use revm_precompile::PrecompileResult;
use bls_verify::BlsVerify;
use pop_verify::PopVerify;
use scilla::ScillaRead;

use crate::exec::{PendingState, ZQ2EvmContext};

#[derive(Debug, Clone)]
pub struct ZQ2PrecompileProvider {
    inner: EthPrecompiles,
}

impl ZQ2PrecompileProvider {
    pub fn new() -> Self {
        Self {
            inner: EthPrecompiles::default(),
        }
    }
}

impl<CTX> PrecompileProvider<CTX> for ZQ2PrecompileProvider
where
    CTX: ContextTr,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        self.inner.set_spec(spec)
    }

    fn run(
        &mut self,
        context: &mut CTX,
        address: &Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {

        // Otherwise, delegate to standard Ethereum precompiles
        self.inner
            .run(context, address, inputs, is_static, gas_limit)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        // Include our custom precompile address along with standard ones
        let mut addresses = vec![];
        addresses.extend(self.inner.warm_addresses());
        Box::new(addresses.into_iter())
    }

    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }
}

pub trait ContextPrecompile<CTX: ContextTr>: Sync + Send {
    fn call(
        &self,
        ctx: &mut CTX,
        target: Address,
        input: &InputsImpl,
        is_static: bool,
        gas_litmit: u64
    ) -> PrecompileResult;
}

pub type ExtendedPrecompileFn<CTX: ContextTr> = fn(&mut CTX, Address, &InputsImpl, bool, u64) -> PrecompileResult;

pub fn get_custom_precompiles<'a, I>() -> Vec<(Address, Arc<dyn ContextPrecompile<ZQ2EvmContext<'a, I>>>)> {
    vec![
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x80"),
            Arc::new(PopVerify),
        ),
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x81"),
            Arc::new(BlsVerify),
        ),
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x92"),
            Arc::new(ScillaRead),
        ),
        // The "Scilla call" precompile also exists at address `0x5a494c53`. However, it is implemented by overwriting
        // the `revm` call handler, rather than using a conventional precompile. This is because it requires extra
        // information which isn't provided by the precompile interface, such as the external context (where the
        // inspector is kept), the `msg.sender` and the `msg.value`.
    ]
}
