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

use crate::{crypto::Hash, node::Node};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("debug_getBadBlocks", debug_get_bad_blocks),
            ("debug_getTrieFlushInterval", debug_get_trie_flush_interval),
            ("debug_storageRangeAt", debug_storage_range_at),
            ("debug_traceBlock", debug_trace_block),
            ("debug_traceBlockByHash", debug_trace_block_by_hash),
            ("debug_traceBlockByNumber", debug_trace_block_by_number),
            ("debug_traceCall", debug_trace_call),
            ("debug_traceTransaction", debug_trace_transaction),
            ("trace_block", trace_block),
            ("trace_call", trace_call),
            ("trace_callMany", trace_call_many),
            ("trace_filter", trace_filter),
            ("trace_rawTransaction", trace_raw_transaction),
            (
                "trace_replayBlockTransactions",
                trace_replay_block_transactions
            ),
            ("trace_replayTransaction", replay_transaction),
            ("trace_transaction", trace_transaction),
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

// trace_block
fn trace_block(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// trace_call
fn trace_call(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// trace_callMany
fn trace_call_many(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// trace_filter
fn trace_filter(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// trace_rawTransaction
fn trace_raw_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// trace_replayBlockTransactions
fn trace_replay_block_transactions(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// trace_transaction
fn trace_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// debug_getBadBlocks
fn debug_get_bad_blocks(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// debug_storageRangeAt
fn debug_storage_range_at(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// debug_getTrieFlushInterval
fn debug_get_trie_flush_interval(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// debug_traceBlock
fn debug_trace_block(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// debug_traceBlockByHash
fn debug_trace_block_by_hash(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// debug_traceCall
fn debug_trace_call(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

// debug_traceTransaction
fn debug_trace_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}
