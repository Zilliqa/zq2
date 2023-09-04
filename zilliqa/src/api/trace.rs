//! The trace API, as documented at <https://openethereum.github.io/JSONRPC-trace-module>.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::H256;

use crate::node::Node;

use super::types::{
    BlockTrace, StateDiff, TraceAction, TraceActionType, TraceCall, TraceCallType, TransactionTrace,
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("trace_replayTransaction", replay_transaction)])
}

fn replay_transaction(params: Params, _node: &Arc<Mutex<Node>>) -> Result<BlockTrace> {
    let mut params = params.sequence();
    let hash: H256 = params.next()?;
    let trace_params: Vec<&str> = params.next()?;
    let trace = if trace_params.contains(&"trace") {
        Some(vec![TransactionTrace {
            trace_address: vec![],
            subtraces: 0,
            action: TraceAction::Call(TraceCall {
                from: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
                    .parse()
                    .unwrap(),
                to: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
                    .parse()
                    .unwrap(),
                value: 0.into(),
                gas: 0.into(),
                input: vec![],
                call_type: TraceCallType::Call,
            }),
            action_type: TraceActionType::Call,
            result: None,
            error: None,
        }])
    } else {
        None
    };
    let vm_trace = if trace_params.contains(&"vmTrace") {
        todo!()
    } else {
        None
    };
    let state_diff = if trace_params.contains(&"stateDiff") {
        Some(StateDiff(BTreeMap::new()))
    } else {
        None
    };
    Ok(BlockTrace {
        output: vec![],
        trace,
        vm_trace,
        state_diff,
        transaction_hash: Some(hash),
    })
}
