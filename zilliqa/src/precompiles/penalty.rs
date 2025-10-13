use std::{
    collections::VecDeque,
    fmt::{self, Display, Formatter},
};

use alloy::primitives::Address;
use ethabi::{ParamType, Token, decode, encode, short_signature};
use revm::interpreter::{Gas, InputsImpl, InstructionResult, InterpreterResult};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{
    constants::{LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_THRESHOLD, MISSED_VIEW_WINDOW},
    crypto::NodePublicKey,
    evm::ZQ2EvmContext,
    precompiles::ContextPrecompile,
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
        let mut deque = VecDeque::new();
        let source = &self.missed_views;
        //TODO(jailing): use binary search to find the range to be copied
        for (view, leader) in source.iter() {
            if *view >= min_view && *view < block_view {
                deque.push_back((*view, *leader));
            }
        }
        ViewHistory {
            missed_views: deque,
            min_view,
        }
    }

    pub fn append_history(
        &mut self,
        new_missed_views: &[(u64, NodePublicKey)],
    ) -> anyhow::Result<bool> {
        // new_missed_views are in descending order
        for (view, leader) in new_missed_views.iter().rev() {
            /*trace::trace!(
                view,
                id = &leader.as_bytes()[..3],
                "++++++++++> adding missed"
            );*/
            self.missed_views.push_back((*view, *leader));
        }
        //TODO(jailing): replace the above loop with the line below once logging is not needed anymore
        //deque.extend(new_missed_views.iter().rev());
        Ok(!new_missed_views.is_empty())
    }

    pub fn prune_history(&mut self, view: u64, max_missed_view_age: u64) -> anyhow::Result<bool> {
        // self.min_view must not be decreased
        let len = self.missed_views.len();
        self.min_view = self
            .min_view
            .max(view.saturating_sub(LAG_BEHIND_CURRENT_VIEW + max_missed_view_age));
        while let Some((view, _leader)) = self.missed_views.front() {
            if *view < self.min_view {
                /*trace::trace!(
                    view,
                    id = &leader.as_bytes()[..3],
                    "----------> deleting missed"
                );*/
                self.missed_views.pop_front();
            } else {
                break; // keys are monotonic
            }
        }
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
        let mut gas_tracker = Gas::new(gas_limit);
        //TODO(#3080): check the gas limit and adjust how much gas the precompile should use
        //info!(gas_limit, "~~~> precompile called with");
        //if gas_limit < 10_000u64 {
        //    return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        //}

        if !gas_tracker.record_cost(10_000u64) {
            return Err("Precompile out of gas".into());
        }
        if input.input.len() < 4 {
            return Err("Provided input must be at least 4-byte long".into());
        }
        let sig = short_signature("jailed", &[ParamType::Bytes, ParamType::Uint(256)]);
        let raw_input = input.input.bytes(ctx);
        if raw_input[..4] != sig {
            return Err("Unable to find handler with given selector".into());
        }
        let Ok(decoded) = decode(&[ParamType::Bytes, ParamType::Uint(256)], &raw_input[4..]) else {
            return Err("ABI input decoding error!".into());
        };
        let leader = decoded.first().unwrap().to_owned().into_bytes().unwrap();
        let view = decoded.last().unwrap().to_owned().into_uint().unwrap();
        // if the current block is beyond the jailing fork activation height when calling the precompile
        // jailing will be applied regardless of whether the view was before or after the fork activation
        if !ctx.chain.fork.validator_jailing {
            let output = encode(&[Token::Bool(false)]);

            return Ok(Some(InterpreterResult::new(
                InstructionResult::default(),
                output.into(),
                gas_tracker,
            )));
        }
        if view.as_u64() > LAG_BEHIND_CURRENT_VIEW
            && view.as_u64() - LAG_BEHIND_CURRENT_VIEW >= ctx.chain.finalized_view
        {
            error!(
                ?view,
                finalized = ctx.chain.finalized_view,
                "~~~~~~~~~~> required missed view history not finalized"
            );
            return Err("Required missed view history not finalized".into());
        }
        let min_view = ctx.chain.view_history.min_view;
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
            return Err("Missed view history not available".into());
        }
        let deque = &ctx.chain.view_history.missed_views;
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
        let jailed = missed >= MISSED_VIEW_THRESHOLD;
        let output = encode(&[Token::Bool(jailed)]);

        Ok(Some(InterpreterResult::new(
            InstructionResult::default(),
            output.into(),
            gas_tracker,
        )))
    }
}
