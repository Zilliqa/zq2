mod bls_verify;
mod penalty;
mod pop_verify;
mod scilla;

use alloy::primitives::Address;
use bls_verify::BlsVerify;
//use penalty::Penalty;
pub use penalty::ViewHistory;
use pop_verify::PopVerify;
use revm::{
    context_interface::{Cfg, ContextTr},
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{InputsImpl, InterpreterResult},
    primitives::address,
};
use revm_context::{BlockEnv, CfgEnv, Journal, TxEnv};
use scilla::ScillaRead;

use crate::{
    evm::ZQ2EvmContext,
    exec::{ExternalContext, PendingState},
    precompiles::{penalty::Penalty, scilla::ScillaCall},
};

#[derive(Debug, Clone)]
pub struct ZQ2PrecompileProvider {
    inner: EthPrecompiles,
}

impl Default for ZQ2PrecompileProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ZQ2PrecompileProvider {
    pub fn new() -> Self {
        Self {
            inner: EthPrecompiles::default(),
        }
    }
}

impl PrecompileProvider<ZQ2EvmContext> for ZQ2PrecompileProvider {
    type Output = InterpreterResult;

    fn set_spec(
        &mut self,
        spec: <<revm::Context<
            BlockEnv,
            TxEnv,
            CfgEnv,
            PendingState,
            Journal<PendingState>,
            ExternalContext,
        > as ContextTr>::Cfg as Cfg>::Spec,
    ) -> bool {
        <EthPrecompiles as PrecompileProvider<ZQ2EvmContext>>::set_spec(&mut self.inner, spec)
    }

    fn run(
        &mut self,
        context: &mut ZQ2EvmContext,
        address: &Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        if let Some(custom_precompile) = CUSTOM_PRECOMPILES.iter().find(|&&(a, _)| a == *address) {
            return custom_precompile
                .1
                .call(context, *address, inputs, is_static, gas_limit);
        }

        // Otherwise, delegate to standard Ethereum precompiles
        self.inner
            .run(context, address, inputs, is_static, gas_limit)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        // Include our custom precompile address along with standard ones
        let mut addresses = vec![];
        addresses.extend(self.inner.warm_addresses());

        const SKIP_WARM_ADDRESSES: [Address; 2] = [PENALTY_ADDRESS, SCILLA_CALL_ADDRESS];

        addresses.extend(
            CUSTOM_PRECOMPILES
                .iter()
                .filter(|(addr, _)| !SKIP_WARM_ADDRESSES.contains(addr))
                .map(|(addr, _)| addr),
        );
        Box::new(addresses.into_iter())
    }

    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address) || CUSTOM_PRECOMPILES.iter().any(|(a, _)| a == address)
    }
}

pub trait ContextPrecompile {
    fn call(
        &self,
        ctx: &mut ZQ2EvmContext,
        target: Address,
        input: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<InterpreterResult>, String>;
}

impl CustomPrecompile {
    pub fn call(
        &self,
        ctx: &mut ZQ2EvmContext,
        target: Address,
        input: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<InterpreterResult>, String> {
        match self {
            CustomPrecompile::PopVerify(p) => p.call(ctx, target, input, is_static, gas_limit),
            CustomPrecompile::BlsVerify(p) => p.call(ctx, target, input, is_static, gas_limit),
            CustomPrecompile::ScillaRead(p) => p.call(ctx, target, input, is_static, gas_limit),
            CustomPrecompile::ScillaCall(p) => p.call(ctx, target, input, is_static, gas_limit),
            CustomPrecompile::Penalty(p) => p.call(ctx, target, input, is_static, gas_limit),
        }
    }
}

pub enum CustomPrecompile {
    PopVerify(PopVerify),
    BlsVerify(BlsVerify),
    ScillaRead(ScillaRead),
    ScillaCall(ScillaCall),
    Penalty(Penalty),
}

pub(crate) const SCILLA_CALL_ADDRESS: Address =
    address!("0x000000000000000000000000000000005a494c53");
pub(crate) const PENALTY_ADDRESS: Address = address!("0x000000000000000000000000000000005a494c82");

pub const CUSTOM_PRECOMPILES: [(Address, CustomPrecompile); 5] = [
    (
        //Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x80"),
        address!("0x000000000000000000000000000000005a494c80"),
        CustomPrecompile::PopVerify(PopVerify),
    ),
    (
        //Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x81"),
        address!("0x000000000000000000000000000000005a494c81"),
        CustomPrecompile::BlsVerify(BlsVerify),
    ),
    (
        //Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x92"),
        address!("0x000000000000000000000000000000005a494c92"),
        CustomPrecompile::ScillaRead(ScillaRead),
    ),
    (
        //Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x53"),
        SCILLA_CALL_ADDRESS,
        CustomPrecompile::ScillaCall(ScillaCall),
    ),
    (
        //Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x82")
        PENALTY_ADDRESS,
        CustomPrecompile::Penalty(Penalty),
    ),
];
