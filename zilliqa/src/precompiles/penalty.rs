use std::{
    collections::VecDeque,
    fmt::{self, Display, Formatter},
    sync::{Arc, Mutex},
};

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
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    constants::{LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_THRESHOLD, MISSED_VIEW_WINDOW},
    crypto::NodePublicKey,
    exec::{ExternalContext, PendingState},
    inspector::ScillaInspector,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewHistory {
    pub missed_views: Arc<Mutex<VecDeque<(u64, NodePublicKey)>>>,
    pub min_view: Arc<Mutex<u64>>,
}

impl Default for ViewHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewHistory {
    pub fn new() -> Self {
        ViewHistory {
            missed_views: Arc::new(Mutex::new(VecDeque::new())),
            min_view: Arc::new(Mutex::new(0)),
        }
    }

    pub fn new_at(&self, finalized_view: u64, max_missed_view_age: u64) -> ViewHistory {
        let min_view = finalized_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW + max_missed_view_age);
        let mut deque = VecDeque::new();
        let source = self.missed_views.lock().unwrap();
        //TODO(#3080): use binary search to find the range to be copied
        for (view, leader) in source.iter() {
            if *view >= min_view && *view < finalized_view {
                deque.push_back((*view, *leader));
            }
        }
        ViewHistory {
            missed_views: Arc::new(Mutex::new(deque)),
            min_view: Arc::new(Mutex::new(min_view)),
        }
    }

    pub fn extend_history(
        &mut self,
        new_missed_views: &[(u64, NodePublicKey)],
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
        //TODO(#3080): replace the above loop with the line below once logging is not needed anymore
        //deque.extend(new_missed_views.iter().rev());
        Ok(!new_missed_views.is_empty())
    }

    pub fn prune_history(&mut self, view: u64, max_missed_view_age: u64) -> anyhow::Result<bool> {
        let mut deque = self.missed_views.lock().unwrap();
        let len = deque.len();
        let mut min_view = self.min_view.lock().unwrap();
        // min_view must not be decreased
        *min_view =
            min_view.max(view.saturating_sub(LAG_BEHIND_CURRENT_VIEW + max_missed_view_age));
        while let Some((view, leader)) = deque.front() {
            if *view < *min_view {
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
}

impl Display for ViewHistory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let deque = self.missed_views.lock().unwrap();
        let front = deque.front();
        let back = deque.back();
        /*let history: Vec<(u64, String)> = deque
        .iter()
        .map(|(view, leader)| {
            let mut id = [0u8; 3];
            id.copy_from_slice(&leader.as_bytes()[..3]);
            let hex_id = id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            (*view, format!("[{}]", hex_id))
        })
        .collect();*/
        let first = match front {
            Some((view, leader)) => {
                let mut id = [0u8; 3];
                id.copy_from_slice(&leader.as_bytes()[..3]);
                let hex_id = id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                Some((*view, format!("[{hex_id}]")))
            }
            None => None,
        };
        let last = match back {
            Some((view, leader)) => {
                let mut id = [0u8; 3];
                id.copy_from_slice(&leader.as_bytes()[..3]);
                let hex_id = id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                Some((*view, format!("[{hex_id}]")))
            }
            None => None,
        };
        let min_view = *self.min_view.lock().unwrap();
        //write!(f, "min: {} missed: {} {:?}", min_view, history.len(), history)
        write!(
            f,
            "min: {} missed: {} {:?}..{:?}",
            min_view,
            deque.len(),
            first.unwrap_or((0, "n/a".to_string())),
            last.unwrap_or((0, "n/a".to_string()))
        )
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
    //TODO(#3080): check the gas limit and adjust how much gas the precompile should use
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
    if !external_context.fork.validator_jailing {
        info!(?view, "==========> jailing not activated yet");
        let output = encode(&[Token::Bool(false)]);
        return Ok(PrecompileOutput::new(10_000u64, output.into()));
    }
    if view.as_u64() > LAG_BEHIND_CURRENT_VIEW
        && view.as_u64() - LAG_BEHIND_CURRENT_VIEW >= external_context.finalized_view
    {
        info!(
            ?view,
            finalized = external_context.finalized_view,
            "~~~~~~~~~~> required missed view history not finalized"
        );
        return Err(
            PrecompileError::Other("Required missed view history not finalized".into()).into(),
        );
    }
    let min_view = *external_context.view_history.min_view.lock().unwrap();
    // fail if the missed view history does not reach back far enough in the past or
    // the queried view is too far in the future based on the currently finalized view
    if min_view > 1
        && view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW) < min_view + MISSED_VIEW_WINDOW
        || view.as_u64() > external_context.finalized_view + LAG_BEHIND_CURRENT_VIEW + 1
    {
        info!(
            ?view,
            min = min_view,
            finalized = external_context.finalized_view,
            "~~~~~~~~~~> missed view history not available"
        );
        return Err(PrecompileError::Other("Missed view history not available".into()).into());
    }
    let deque = external_context.view_history.missed_views.lock().unwrap();
    // binary search to find the relevant missed views in O(log(n))
    let (first_slice, second_slice) = deque.as_slices();
    let search_slice = |slice: &[(u64, NodePublicKey)], target: u64| {
        slice.binary_search_by_key(&target, |&(key, _)| key)
    };
    let to = view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW);
    let from = to.saturating_sub(MISSED_VIEW_WINDOW);
    let (first_start_idx, first_end_idx) = (
        search_slice(first_slice, from).unwrap_or_else(|i| i),
        search_slice(first_slice, to).unwrap_or_else(|i| i),
    );
    let first_range = &first_slice[first_start_idx..first_end_idx];
    // filter the missed views that had the same leader as the selected one
    let filter = |(key, value): &(u64, NodePublicKey)| {
        if value == &NodePublicKey::from_bytes(leader.as_slice()).unwrap() {
            Some(*key)
        } else {
            None
        }
    };
    let missed = if second_slice.is_empty() {
        first_range.iter().filter_map(filter).count()
    } else {
        let (second_start_idx, second_end_idx) = (
            search_slice(second_slice, from).unwrap_or_else(|i| i),
            search_slice(second_slice, to).unwrap_or_else(|i| i),
        );
        let second_range = &second_slice[second_start_idx..second_end_idx];
        first_range
            .iter()
            .chain(second_range.iter())
            .filter_map(filter)
            .count()
    };
    /*let missed = deque
    .iter()
    .filter_map(|(key, value)| {
        if *key < view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW)
            && key + MISSED_VIEW_WINDOW >= view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW)
            && value == &NodePublicKey::from_bytes(leader.as_slice()).unwrap()
        {
            Some(key)
        } else {
            None
        }
    })
    .count();*/
    let jailed = missed >= MISSED_VIEW_THRESHOLD;
    info!(
        jailed,
        missed,
        ?view,
        min_view,
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
