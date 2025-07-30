use std::sync::Arc;

use ethabi::{ParamType, Token, decode, encode, short_signature};
use revm::{
    //ContextStatefulPrecompile,
    FrameOrResult,
    InnerEvmContext,
    handler::register::EvmHandler,
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    precompile::PrecompileError,
    primitives::{
        Address, Bytes, EVMError, PrecompileErrors, PrecompileOutput, PrecompileResult,
        alloy_primitives::private::alloy_rlp::Encodable,
    },
};
use tracing::info;

use crate::{
    crypto::NodePublicKey,
    exec::{ExternalContext, PendingState},
    inspector::ScillaInspector,
};

/*
pub struct Penalty;

impl Penalty {
    fn jailed(
        input: &[u8],
        gas_limit: u64,
        _context: &mut InnerEvmContext<PendingState>,
    ) -> PrecompileResult {
        if gas_limit < 10_000u64 {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }
        let Ok(decoded) = decode(
            &[ParamType::Bytes, ParamType::Uint(256)],
            input,
        ) else {
            return Err(PrecompileError::Other("ABI input decoding error!".into()).into());
        };
        let output = encode(&[Token::Bool(false)]);
        Ok(PrecompileOutput::new(
            10_000u64,
            output.into(),
        ))
    }
}

impl ContextStatefulPrecompile<PendingState> for Penalty {
    fn call(
        &self,
        input: &Bytes,
        gas_limit: u64,
        context: &mut InnerEvmContext<PendingState>,
    ) -> PrecompileResult {
        if input.length() < 4 {
            return Err(PrecompileError::Other(
                "Provided input must be at least 4-byte long".into(),
            )
            .into());
        }

        let dispatch_table: [([u8; 4], _); 1] = [(
            short_signature(
                "jailed",
                &[ParamType::Bytes, ParamType::Uint(256)],
            ),
            Self::jailed,
        )];

        let Some(handler) = dispatch_table
            .iter()
            .find(|&predicate| predicate.0 == input[..4])
        else {
            return Err(PrecompileError::Other(
                "Unable to find handler with given selector".to_string(),
            )
            .into());
        };

        handler.1(&input[4..], gas_limit, context)
    }
}
*/

pub fn dispatch<I: ScillaInspector>(
    input: &CallInputs,
    _gas_limit: u64,
    _context: &mut InnerEvmContext<PendingState>,
    external_context: &mut ExternalContext<I>,
) -> PrecompileResult {
    //TODO: check gas limit?
    //if gas_limit < 10_000u64 {
    //    return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    //}
    if input.input.length() < 4 {
        return Err(
            PrecompileError::Other("Provided input must be at least 4-byte long".into()).into(),
        );
    }
    let sig = short_signature("jailed", &[ParamType::Bytes, ParamType::Uint(256)]);
    if input.input[..4] != sig {
        return Err(PrecompileError::Other(
            "Unable to find handler with given selector".to_string(),
        )
        .into());
    }
    let Ok(decoded) = decode(&[ParamType::Bytes, ParamType::Uint(256)], &input.input[4..]) else {
        return Err(PrecompileError::Other("ABI input decoding error!".into()).into());
    };
    let pubkey = decoded.first().unwrap().to_owned().into_bytes().unwrap();
    let view = decoded.last().unwrap().to_owned().into_uint().unwrap();
    //TODO: ensure the available history of missed views is sufficient for the view number passed as input
    let deque = external_context.missed_views.lock().unwrap();
    let missed_views: Vec<&u64> = deque
        .iter()
        .filter(|(key, value)| {
            *key < view.as_u64()
                && key + 100 >= view.as_u64()
                && value == &NodePublicKey::from_bytes(pubkey.as_slice()).unwrap()
        })
        .map(|(key, _)| key)
        .collect();
    //TODO: nice to have: don't punish proposers if their blocks were reorganized because of the next leader's fault, i.e.
    //      if view k-1 is not missing, but views k and k+1 are missing, then the proposal from view k was reorganized
    let missed = missed_views.len();
    //TODO: prevent that we return true for all the validators in the committee or even just keep querying the precompile too many times to find one
    let jailed = missed >= 3;
    let id = &pubkey[..3];
    info!(jailed, missed, ?view, id, "----------> leader");
    let output = encode(&[Token::Bool(jailed)]);
    Ok(PrecompileOutput::new(10_000u64, output.into()))
}

pub fn penalty_handle_register<I: ScillaInspector>(
    handler: &mut EvmHandler<'_, ExternalContext<I>, PendingState>,
) {
    let prev_handle = handler.execution.call.clone();
    handler.execution.call = Arc::new(move |ctx, inputs| {
        if inputs.bytecode_address != Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x82") {
            return prev_handle(ctx, inputs);
        }

        let gas = Gas::new(inputs.gas_limit);

        let outcome = dispatch(&inputs, gas.limit(), &mut ctx.evm.inner, &mut ctx.external);

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas,
            output: Bytes::new(),
        };

        match outcome {
            Ok(output) => {
                if result.gas.record_cost(output.gas_used) {
                    result.result = InstructionResult::Return;
                    result.output = output.bytes;
                } else {
                    result.result = InstructionResult::PrecompileOOG;
                }
            }
            Err(PrecompileErrors::Error(e)) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
            }
            Err(PrecompileErrors::Fatal { msg }) => return Err(EVMError::Precompile(msg)),
        }

        Ok(FrameOrResult::new_call_result(
            result,
            inputs.return_memory_offset.clone(),
        ))
    });
}
