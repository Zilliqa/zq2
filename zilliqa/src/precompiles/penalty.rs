use std::{
    collections::VecDeque,
    fmt::{self, Display, Formatter},
    sync::{Arc, Mutex},
};

use anyhow;
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
    constants::{LAG_BEHIND_CURRENT_VIEW, MAX_MISSED_VIEW_AGE},
    crypto::NodePublicKey,
    exec::{ExternalContext, PendingState},
    inspector::ScillaInspector,
    message::BlockHeader,
    state::State,
};

#[derive(Clone, Debug)]
pub struct ViewHistory {
    pub missed_views: Arc<Mutex<VecDeque<(u64, NodePublicKey)>>>,
    pub starting_view: Arc<Mutex<u64>>,
}

impl ViewHistory {
    pub fn new() -> Self {
        ViewHistory {
            missed_views: Arc::new(Mutex::new(VecDeque::new())),
            starting_view: Arc::new(Mutex::new(0)),
        }
    }

    pub fn extend_history(
        &mut self,
        new_missed_views: &Vec<(u64, NodePublicKey)>,
    ) -> anyhow::Result<bool> {
        let mut deque = self.missed_views.lock().unwrap();
        for (view, leader) in new_missed_views.iter().rev() {
            info!(
                view,
                id = &leader.as_bytes()[..3],
                "++++++++++> adding missed"
            );
            deque.push_back((*view, *leader));
        }
        //TODO(#3080): replace the above loop with the line below
        //deque.extend(new_missed_views.iter().rev());
        Ok(!new_missed_views.is_empty())
    }

    pub fn prune_history(&mut self, view: u64) -> anyhow::Result<bool> {
        let mut deque = self.missed_views.lock().unwrap();
        let len = deque.len();
        let mut starting_view = self.starting_view.lock().unwrap();
        *starting_view = view.saturating_sub(LAG_BEHIND_CURRENT_VIEW + MAX_MISSED_VIEW_AGE);
        while let Some((view, leader)) = deque.front() {
            if *view < *starting_view {
                info!(
                    view,
                    id = &leader.as_bytes()[..3],
                    "----------> deleting missed"
                );
                deque.pop_front();
            } else {
                break; // keys are monotonic
            }
        }
        Ok(deque.len() < len)
    }

    pub fn populate_history(
        &mut self,
        state: State,
        block_number: u64,
        block_view: u64,
        start_view: u64,
    ) -> anyhow::Result<()> {
        let block_header = BlockHeader {
            number: block_number,
            ..Default::default()
        };
        for view in (start_view + 1..block_view).rev() {
            if let Ok(leader) = state.leader(view, block_header) {
                let mut deque = self.missed_views.lock().unwrap();
                info!(
                    view,
                    id = &leader.as_bytes()[..3],
                    "~~~~~~~~~~> restoring missed"
                );
                deque.push_front((view, leader));
            }
        }
        Ok(())
    }
}

impl Display for ViewHistory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let deque = self.missed_views.lock().unwrap();
        let history: Vec<(u64, String)> = deque
            .iter()
            .map(|(view, leader)| {
                let mut id = [0u8; 3];
                id.copy_from_slice(&leader.as_bytes()[..3]);
                let hex_id = id
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<Vec<_>>()
                    .join(" ");
                (*view, format!("[{}]", hex_id))
            })
            .collect();
        let starting = *self.starting_view.lock().unwrap();
        write!(f, "starting: {} missed: {:?}", starting, history,)
    }
}

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
    //TODO(#3080): check gas limit?
    //info!(gas_limit, "~~~> precompile called with");
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
    let leader = decoded.first().unwrap().to_owned().into_bytes().unwrap();
    let view = decoded.last().unwrap().to_owned().into_uint().unwrap();
    let starting_view = *external_context.view_history.starting_view.lock().unwrap();
    //TODO(#3080): check if view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW) >= finalized_view
    if starting_view > 1
        && view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW) < starting_view + 100
    {
        info!(
            ?view,
            starting_view, "~~~~~~~~~~> missed view history not available"
        );
        return Err(PrecompileError::Other("Missed view history not available".into()).into());
    }
    let deque = external_context.view_history.missed_views.lock().unwrap();
    let missed = deque
        .iter()
        .filter_map(|(key, value)| {
            if *key < view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW)
                && key + 100 >= view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW)
                && value == &NodePublicKey::from_bytes(leader.as_slice()).unwrap()
            {
                Some(key)
            } else {
                None
            }
        })
        .count();
    let jailed = missed >= 3;
    info!(
        jailed,
        missed,
        ?view,
        starting_view,
        id = &leader[..3],
        "==========> leader"
    );
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
