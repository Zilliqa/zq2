use std::{
    ops::RangeInclusive,
    sync::{Arc, Mutex},
};

use alloy::{
    eips::BlockNumberOrTag,
    rpc::types::trace::geth::{GethDebugTracingOptions, TraceResult},
};
use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};

use crate::{cfg::EnabledApi, node::Node};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("debug_getBadBlocks", debug_get_bad_blocks),
            ("debug_getTrieFlushInterval", debug_get_trie_flush_interval),
            ("debug_storageRangeAt", debug_storage_range_at),
            ("debug_traceBlock", debug_trace_block),
            ("debug_traceBlockByHash", debug_trace_block_by_hash),
            ("debug_traceBlockByNumber", debug_trace_block_by_number),
            ("debug_traceCall", debug_trace_call),
            ("debug_traceTransaction", debug_trace_transaction),
            ("debug_storedBlockRange", debug_stored_block_range)
        ]
    )
}

/// TODO: place-holder for now, feel free to change it.
fn debug_stored_block_range(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<RangeInclusive<u64>> {
    node.lock().unwrap().db.available_range()
}

/// debug_getBadBlocks
fn debug_get_bad_blocks(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method debug_getBadBlocks is not implemented yet"
    ))
}

/// debug_getTrieFlushInterval
fn debug_get_trie_flush_interval(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method debug_getTrieFlushInterval is not implemented yet"
    ))
}

/// debug_storageRangeAt
fn debug_storage_range_at(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method debug_storageRangeAt is not implemented yet"
    ))
}

/// debug_traceBlock
fn debug_trace_block(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method debug_traceBlock is not implemented yet"
    ))
}

/// debug_traceBlockByHash
fn debug_trace_block_by_hash(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method debug_traceBlockByHash is not implemented yet"
    ))
}

/// debug_traceBlockByNumber
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

/// debug_traceCall
fn debug_trace_call(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method debug_traceCall is not implemented yet"))
}

/// debug_traceTransaction
fn debug_trace_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method debug_traceTransaction is not implemented yet"
    ))
}
