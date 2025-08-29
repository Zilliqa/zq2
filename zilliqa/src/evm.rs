use revm::context_interface::ContextSetters;
use revm::handler::{EthFrame, EvmTr, FrameInitOrResult, FrameTr, ItemOrResult, PrecompileProvider};
use revm::handler::instructions::EthInstructions;
use revm::interpreter::interpreter::EthInterpreter;
use revm::primitives::hardfork::SpecId;
use revm_context::{BlockEnv, CfgEnv, Context, ContextError, ContextTr, Database, Evm, FrameStack, Journal, TxEnv};
use revm_inspector::{Inspector, InspectorEvmTr, JournalExt};
use crate::exec::{ExternalContext, PendingState};
use crate::precompiles::ZQ2PrecompileProvider;

pub (crate) const SPEC_ID: SpecId = SpecId::SHANGHAI;
pub type ZQ2EvmContext<'a> = Context<BlockEnv, TxEnv, CfgEnv, PendingState, Journal<PendingState>, ExternalContext<'a>>;
pub (crate) fn new_zq2_evm_ctx(db: PendingState, chain: ExternalContext) -> ZQ2EvmContext {
    let ctx: Context<BlockEnv, TxEnv, CfgEnv, PendingState, Journal<PendingState>> = Context::new(db, SPEC_ID);
    ctx.with_chain(chain)
}

pub struct ZQ2Evm<'a, I>(
    pub  Evm<
        ZQ2EvmContext<'a>,
        I,
        EthInstructions<EthInterpreter, ZQ2EvmContext<'a>>,
        ZQ2PrecompileProvider,
        EthFrame<EthInterpreter>,
    >,
);

impl<'a, I> ZQ2Evm<'a, I>
{
    pub fn new(ctx: ZQ2EvmContext<'a>, inspector: I) -> ZQ2Evm<'a, I> {
        let mut precompiles = ZQ2PrecompileProvider::new();
        <ZQ2PrecompileProvider as PrecompileProvider<ZQ2EvmContext<'a>>>::set_spec(&mut precompiles, SPEC_ID);
        ZQ2Evm (Evm {
            ctx,
            inspector,
            instruction: EthInstructions::new_mainnet(),
            precompiles,
            frame_stack: FrameStack::new(),
        })
    }
}

impl<'a, I> EvmTr for ZQ2Evm<'a, I>
{
    type Context = ZQ2EvmContext<'a>;
    type Instructions = EthInstructions<EthInterpreter, ZQ2EvmContext<'a>>;
    type Precompiles = ZQ2PrecompileProvider;
    type Frame = EthFrame<EthInterpreter>;

    fn ctx(&mut self) -> &mut Self::Context {
        &mut self.0.ctx
    }

    fn ctx_ref(&self) -> &Self::Context {
        self.0.ctx_ref()
    }

    fn ctx_instructions(&mut self) -> (&mut Self::Context, &mut Self::Instructions) {
        self.0.ctx_instructions()
    }

    fn ctx_precompiles(&mut self) -> (&mut Self::Context, &mut Self::Precompiles) {
        self.0.ctx_precompiles()
    }

    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        self.0.frame_stack()
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_init(frame_input)
    }

    fn frame_run(
        &mut self,
    ) -> Result<
        FrameInitOrResult<Self::Frame>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_run()
    }

    fn frame_return_result(
        &mut self,
        frame_result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<
        Option<<Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_return_result(frame_result)
    }
}

impl<'a, I: Inspector<ZQ2EvmContext<'a>, EthInterpreter>> InspectorEvmTr for ZQ2Evm<'a, I>
{
    type Inspector = I;

    fn inspector(&mut self) -> &mut Self::Inspector {
        self.0.inspector()
    }

    fn ctx_inspector(&mut self) -> (&mut Self::Context, &mut Self::Inspector) {
        self.0.ctx_inspector()
    }

    fn ctx_inspector_frame(
        &mut self,
    ) -> (&mut Self::Context, &mut Self::Inspector, &mut Self::Frame) {
        self.0.ctx_inspector_frame()
    }

    fn ctx_inspector_frame_instructions(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Inspector,
        &mut Self::Frame,
        &mut Self::Instructions,
    ) {
        self.0.ctx_inspector_frame_instructions()
    }
}

// impl<I: Inspector<PendingState>> GetInspector<PendingState> for ExternalContext<'_, I> {
//     fn get_inspector(&mut self) -> &mut impl Inspector<PendingState> {
//         &mut self.inspector
//     }
// }
