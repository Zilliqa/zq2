use revm::context_interface::ContextSetters;
use revm::context_interface::result::{EVMError, ExecResultAndState, ExecutionResult, HaltReason, InvalidTransaction, ResultAndState};
use revm::ExecuteEvm;
use revm::handler::{EthFrame, EvmTr, FrameInitOrResult, FrameTr, ItemOrResult, MainnetHandler, PrecompileProvider};
use revm::handler::instructions::EthInstructions;
use revm::interpreter::FrameInput;
use revm::interpreter::interpreter::EthInterpreter;
use revm::primitives::Address;
use revm::primitives::hardfork::SpecId;
use revm::state::EvmState;
use revm_context::{BlockEnv, CfgEnv, Context, ContextError, ContextTr, Database, Evm, FrameStack, Journal, TxEnv};
use revm_inspector::{InspectEvm, Inspector, InspectorEvmTr, InspectorHandler, JournalExt};
use crate::exec::{DatabaseError, ExternalContext, PendingState};
use crate::precompiles::ZQ2PrecompileProvider;

pub (crate) const SPEC_ID: SpecId = SpecId::SHANGHAI;
pub type ZQ2EvmContext = Context<BlockEnv, TxEnv, CfgEnv, PendingState, Journal<PendingState>, ExternalContext>;
pub (crate) fn new_zq2_evm_ctx(db: PendingState, chain: ExternalContext) -> ZQ2EvmContext {
    let ctx: Context<BlockEnv, TxEnv, CfgEnv, PendingState, Journal<PendingState>> = Context::new(db, SPEC_ID);
    ctx.with_chain(chain)
}

pub struct ZQ2Evm<I>(
    pub  Evm<
        ZQ2EvmContext,
        I,
        EthInstructions<EthInterpreter, ZQ2EvmContext>,
        ZQ2PrecompileProvider,
        EthFrame<EthInterpreter>,
    >,
);

impl<I: Inspector<ZQ2EvmContext>> ZQ2Evm<I>
{
    pub fn new(ctx: ZQ2EvmContext, inspector: I) -> ZQ2Evm<I> {
        let mut precompiles = ZQ2PrecompileProvider::new();
        <ZQ2PrecompileProvider as PrecompileProvider<ZQ2EvmContext>>::set_spec(&mut precompiles, SPEC_ID);
        ZQ2Evm (Evm {
            ctx,
            inspector,
            instruction: EthInstructions::new_mainnet(),
            precompiles,
            frame_stack: FrameStack::new(),
        })
    }

    pub fn transact(&mut self, tx: TxEnv) -> Result<ResultAndState<HaltReason>, EVMError<DatabaseError>> {
        self.0.set_tx(tx);
        self.replay()
    }

    pub fn inspect_txn(&mut self, tx: TxEnv) -> Result<ResultAndState<HaltReason>, EVMError<DatabaseError>> {
        let output = self.inspect_one_tx(tx)?;
        let state = self.0.finalize();
        Ok(ExecResultAndState::new(output, state))
    }
}

impl<I> EvmTr for ZQ2Evm<I>
{
    type Context = ZQ2EvmContext;
    type Instructions = EthInstructions<EthInterpreter, ZQ2EvmContext>;
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
        // Reserve enough space to store the caller.
        let current_depth = self.0.journaled_state.depth;
        let caller_depth = self.0.chain.callers.len();
        self.0.chain.callers.reserve(
            (current_depth + 1).saturating_sub(caller_depth),
        );
        for _ in self.0.chain.callers.len()..(self.0.journaled_state.depth + 1) {
            self.0.chain.callers.push(Address::ZERO);
        }

        let caller = match &frame_input.frame_input {
            FrameInput::Empty => Address::ZERO,
            FrameInput::Call(call) => call.caller,
            FrameInput::Create(create) => create.caller,
        };
        let depth = self.0.journaled_state.depth;
        self.0.chain.callers[depth] = caller;

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
    >
    {
        if frame_result.interpreter_result().is_error() || frame_result.interpreter_result().is_revert() {
            self.0.chain.has_evm_failed = true;
        }
        self.0.frame_return_result(frame_result)
    }
}

impl<I: Inspector<ZQ2EvmContext, EthInterpreter>> ExecuteEvm for ZQ2Evm<I> {
    type ExecutionResult = ExecutionResult<HaltReason>;
    type State = EvmState;
    type Error = EVMError<DatabaseError, InvalidTransaction>;
    type Tx = TxEnv;
    type Block = BlockEnv;

    fn set_block(&mut self, block: Self::Block) {
        self.0.ctx.set_block(block);
    }

    fn transact_one(&mut self, tx: Self::Tx) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.transact_one(tx)
    }

    fn finalize(&mut self) -> Self::State {
        self.0.finalize()
    }

    fn replay(&mut self) -> Result<ExecResultAndState<Self::ExecutionResult, Self::State>, Self::Error> {
        self.0.replay()
    }
}

impl<'a, I: Inspector<ZQ2EvmContext, EthInterpreter>> InspectEvm for ZQ2Evm<I>
{
    type Inspector = I;

    fn set_inspector(&mut self, inspector: Self::Inspector) {
        self.0.inspector = inspector;
    }

    fn inspect_one_tx(&mut self, tx: Self::Tx) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.inspect_one_tx(tx)
    }
}

impl<I: Inspector<ZQ2EvmContext, EthInterpreter>> InspectorEvmTr for ZQ2Evm<I>
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
