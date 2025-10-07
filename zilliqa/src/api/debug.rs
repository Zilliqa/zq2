use std::sync::Arc;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::B256,
    rpc::types::trace::geth::{GethDebugTracingOptions, TraceResult},
};
use anyhow::{Result, anyhow};
use jsonrpsee::{RpcModule, types::Params};

use crate::{
    api::{
        HandlerType, disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook,
        rpc_base_attributes,
    },
    cfg::EnabledApi,
    crypto::Hash,
    inspector,
    node::Node,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            (
                "debug_getBadBlocks",
                debug_get_bad_blocks,
                HandlerType::Slow
            ),
            (
                "debug_getTrieFlushInterval",
                debug_get_trie_flush_interval,
                HandlerType::Slow
            ),
            (
                "debug_storageRangeAt",
                debug_storage_range_at,
                HandlerType::Slow
            ),
            ("debug_traceBlock", debug_trace_block, HandlerType::Slow),
            (
                "debug_traceBlockByHash",
                debug_trace_block_by_hash,
                HandlerType::Slow
            ),
            (
                "debug_traceBlockByNumber",
                debug_trace_block_by_number,
                HandlerType::Slow
            ),
            ("debug_traceCall", debug_trace_call, HandlerType::Slow),
            (
                "debug_traceTransaction",
                debug_trace_transaction,
                HandlerType::Slow
            ),
        ]
    )
}

/// debug_getBadBlocks
fn debug_get_bad_blocks(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method debug_getBadBlocks is not implemented yet"
    ))
}

/// debug_getTrieFlushInterval
fn debug_get_trie_flush_interval(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method debug_getTrieFlushInterval is not implemented yet"
    ))
}

/// debug_storageRangeAt
fn debug_storage_range_at(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method debug_storageRangeAt is not implemented yet"
    ))
}

/// debug_traceBlock
fn debug_trace_block(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method debug_traceBlock is not implemented yet"
    ))
}

/// debug_traceBlockByHash
fn debug_trace_block_by_hash(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method debug_traceBlockByHash is not implemented yet"
    ))
}

/// debug_traceBlockByNumber
fn debug_trace_block_by_number(params: Params, node: &Arc<Node>) -> Result<Vec<TraceResult>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let trace_type: Option<GethDebugTracingOptions> = params.optional_next()?;

    node.debug_trace_block(block_number, trace_type.unwrap_or_default())
}

/// debug_traceCall
fn debug_trace_call(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!("API method debug_traceCall is not implemented yet"))
}

/// debug_traceTransaction
fn debug_trace_transaction(params: Params, node: &Arc<Node>) -> Result<TraceResult> {
    let mut params = params.sequence();
    let txn_hash: B256 = params.next()?;
    let txn_hash: Hash = txn_hash.into();
    let trace_opts: Option<GethDebugTracingOptions> = params.optional_next()?;

    // Get transaction and its receipt to find the block it was included in
    let receipt = node
        .get_transaction_receipt(txn_hash)?
        .ok_or_else(|| anyhow!("transaction not mined: {txn_hash}"))?;

    let block = node
        .get_block(receipt.block_hash)?
        .ok_or_else(|| anyhow!("missing block: {}", receipt.block_hash))?;

    let parent = node
        .get_block(block.parent_hash())?
        .ok_or_else(|| anyhow!("missing parent block: {}", block.parent_hash()))?;

    let mut state = node
        .consensus
        .read()
        .state()
        .at_root(parent.state_root_hash().into());

    // Find the transaction's index in the block
    let txn_index = block
        .transactions
        .iter()
        .position(|&h| h == txn_hash)
        .ok_or_else(|| anyhow!("transaction not found in specified block"))?;

    // Apply all transactions before the target transaction
    for &prev_tx_hash in &block.transactions[0..txn_index] {
        let prev_tx = node
            .get_transaction_by_hash(prev_tx_hash)?
            .ok_or_else(|| anyhow!("transaction not found: {prev_tx_hash}"))?;

        state.apply_transaction(prev_tx, block.header, inspector::noop(), false)?;
    }

    // Get the target transaction
    let _txn = node
        .get_transaction_by_hash(txn_hash)?
        .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;

    // Use default options if none provided
    let trace_opts = trace_opts.unwrap_or_default();

    // Debug trace the transaction
    let trace_result =
        node.debug_trace_transaction(&mut state, txn_hash, txn_index, &block, trace_opts)?;

    trace_result.ok_or_else(|| anyhow!("Failed to trace transaction"))
}
