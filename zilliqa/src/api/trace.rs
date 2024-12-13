use std::sync::{Arc, Mutex};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::B256,
    rpc::types::trace::{
        geth::{GethDebugTracingOptions, TraceResult},
        parity::TraceResults,
    },
};
use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use crate::{cfg::EnabledApi, crypto::Hash, node::Node};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("trace_replayTransaction", replay_transaction),
            ("debug_traceBlockByNumber", debug_trace_block_by_number),
        ]
    )
}

fn replay_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<TraceResults> {
    let mut params = params.sequence();
    let txn_hash: B256 = params.next()?;
    let txn_hash: Hash = txn_hash.into();
    let trace_types = params.next()?;

    let trace = node
        .lock()
        .unwrap()
        .trace_evm_transaction(txn_hash, &trace_types)?;

    Ok(trace)
}

fn debug_trace_block_by_number(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Vec<TraceResult>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let trace_type: Option<GethDebugTracingOptions> = params.next()?;

    node.lock()
        .unwrap()
        .debug_trace_block(block_number, trace_type.unwrap_or_default())
}
