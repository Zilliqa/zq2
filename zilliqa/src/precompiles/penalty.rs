use std::{
    collections::VecDeque,
    fmt::{self, Display, Formatter},
};

use alloy::primitives::{Address, Bytes};
use ethabi::{ParamType, Token, decode, encode, short_signature};
use revm::interpreter::{Gas, InputsImpl, InstructionResult, InterpreterResult};
use revm_precompile::{PrecompileError, PrecompileOutput};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{
    constants::{LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_THRESHOLD, MISSED_VIEW_WINDOW},
    crypto::NodePublicKey,
    evm::ZQ2EvmContext,
    precompiles::{ContextPrecompile, scilla::PrecompileErrors},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewHistory {
    pub missed_views: VecDeque<(u64, NodePublicKey)>,
    pub min_view: u64,
}

impl Default for ViewHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewHistory {
    pub fn new() -> Self {
        ViewHistory {
            missed_views: VecDeque::new(),
            min_view: 0,
        }
    }

    pub fn new_at(
        &self,
        parent_view: u64,
        block_view: u64,
        max_missed_view_age: u64,
    ) -> ViewHistory {
        let min_view = parent_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW + max_missed_view_age);
        // Find the range of elements within [min_view, block_view)
        let start_idx = self
            .missed_views
            .partition_point(|(view, _)| *view < min_view);
        let end_idx = self
            .missed_views
            .partition_point(|(view, _)| *view < block_view);

        // Copy the elements in that range into the deque
        let deque = self
            .missed_views
            .range(start_idx..end_idx)
            .copied()
            .collect();
        ViewHistory {
            missed_views: deque,
            min_view,
        }
    }

    pub fn append_history(
        &mut self,
        new_missed_views: &VecDeque<(u64, NodePublicKey)>,
    ) -> anyhow::Result<bool> {
        if !new_missed_views.is_empty() && !self.missed_views.is_empty() {
            // new_missed_views are in ascending order
            anyhow::ensure!(
                new_missed_views.front().unwrap().0 > self.missed_views.back().unwrap().0,
                "Appending older missed_views"
            );
        }
        let len = self.missed_views.len();
        self.missed_views.extend(new_missed_views.iter().cloned());
        Ok(len < self.missed_views.len())
    }

    pub fn prune_history(&mut self, view: u64, max_missed_view_age: u64) -> anyhow::Result<bool> {
        let len = self.missed_views.len();
        // self.min_view must not be decreased
        self.min_view = self
            .min_view
            .max(view.saturating_sub(LAG_BEHIND_CURRENT_VIEW + max_missed_view_age));
        let split = self
            .missed_views
            .partition_point(|(v, _)| *v < self.min_view); // use binary search, instead of linear
        self.missed_views.drain(..split);
        Ok(self.missed_views.len() < len)
    }
}

impl Display for ViewHistory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let front = self.missed_views.front();
        let back = self.missed_views.back();
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
        write!(
            f,
            "min: {} missed: {} {:?}..{:?}",
            self.min_view,
            self.missed_views.len(),
            first.unwrap_or((0, "n/a".to_string())),
            last.unwrap_or((0, "n/a".to_string()))
        )
    }
}

pub struct Penalty;

impl ContextPrecompile for Penalty {
    fn call(
        &self,
        ctx: &mut ZQ2EvmContext,
        _dest: Address,
        input: &InputsImpl,
        _is_static: bool,
        gas_limit: u64,
    ) -> anyhow::Result<Option<InterpreterResult>, String> {
        let gas = Gas::new(gas_limit);

        let outcome = call_penalty(input, gas.limit(), ctx);

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
            Err(PrecompileErrors::Fatal { msg }) => return Err(msg),
        }

        Ok(Some(result))
    }
}

fn call_penalty(
    input: &InputsImpl,
    gas_limit: u64,
    ctx: &mut ZQ2EvmContext,
) -> Result<PrecompileOutput, PrecompileErrors> {
    //TODO(#3080): check the gas limit and adjust how much gas the precompile should use
    //info!(gas_limit, "~~~> precompile called with");
    //if gas_limit < 10_000u64 {
    //    return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    //}
    const REQUIRED_GAS: u64 = 10_000;

    if gas_limit < REQUIRED_GAS {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            "Precompile out of gas".into(),
        )));
    }
    if input.input.len() < 4 {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            "Provided input must be at least 4-byte long".into(),
        )));
    }
    let sig = short_signature("jailed", &[ParamType::Bytes, ParamType::Uint(256)]);
    let raw_input = input.input.bytes(ctx);
    if raw_input[..4] != sig {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            "Unable to find handler with given selector".into(),
        )));
    }
    let Ok(decoded) = decode(&[ParamType::Bytes, ParamType::Uint(256)], &raw_input[4..]) else {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            "ABI input decoding error!".into(),
        )));
    };
    let leader = decoded
        .first()
        .ok_or(PrecompileErrors::Error(PrecompileError::Other(
            "Can't decode leader".to_string(),
        )))?
        .to_owned()
        .into_bytes()
        .ok_or(PrecompileErrors::Error(PrecompileError::Other(
            "Can't decode leader".to_string(),
        )))?;
    let view = decoded
        .last()
        .ok_or(PrecompileErrors::Error(PrecompileError::Other(
            "Can't decode view".to_string(),
        )))?
        .to_owned()
        .into_uint()
        .ok_or(PrecompileErrors::Error(PrecompileError::Other(
            "Can't decode view".to_string(),
        )))?;
    // if the current block is beyond the jailing fork activation height when calling the precompile
    // jailing will be applied regardless of whether the view was before or after the fork activation
    if !ctx.chain.fork.validator_jailing {
        let output = encode(&[Token::Bool(false)]);

        return Ok(PrecompileOutput::new(REQUIRED_GAS, output.into()));
    }
    if view.as_u64() > LAG_BEHIND_CURRENT_VIEW
        && view.as_u64() - LAG_BEHIND_CURRENT_VIEW >= ctx.chain.finalized_view
    {
        error!(
            ?view,
            finalized = ctx.chain.finalized_view,
            "~~~~~~~~~~> required missed view history not finalized"
        );
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            "Required missed view history not finalized".into(),
        )));
    }
    let min_view = ctx.chain.view_history.read().min_view;
    // fail if the missed view history does not reach back far enough in the past or
    // the queried view is too far in the future based on the currently finalized view
    if min_view > 1
        && view.as_u64().saturating_sub(LAG_BEHIND_CURRENT_VIEW) < min_view + MISSED_VIEW_WINDOW
        || view.as_u64() > ctx.chain.finalized_view + LAG_BEHIND_CURRENT_VIEW + 1
    {
        debug!(
            ?view,
            min = min_view,
            finalized = ctx.chain.finalized_view,
            "~~~~~~~~~~> missed view history not available"
        );
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            "Missed view history not available".into(),
        )));
    }
    let deque = &ctx.chain.view_history.read().missed_views;
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
        if let Ok(decoded) = NodePublicKey::from_bytes(leader.as_slice()) {
            if decoded == *value {
                return Some(*key);
            }
            None
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
    let jailed = missed >= MISSED_VIEW_THRESHOLD;
    let output = encode(&[Token::Bool(jailed)]);

    Ok(PrecompileOutput::new(REQUIRED_GAS, output.into()))
}
