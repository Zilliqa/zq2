use std::sync::Arc;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, B256},
    rpc::types::trace::parity::{TraceResults, TraceType},
};
use anyhow::{Result, anyhow};
use jsonrpsee::{RpcModule, types::Params};
use revm_inspectors::tracing::{TracingInspector, TracingInspectorConfig};
use serde::Deserialize;

use crate::{
    api::{
        HandlerType, disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook,
        rpc_base_attributes,
    },
    cfg::EnabledApi,
    crypto::Hash,
    exec::{PendingState, TransactionApplyResult},
    node::Node,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("trace_block", trace_block, HandlerType::Slow),
            ("trace_call", trace_call, HandlerType::Slow),
            ("trace_callMany", trace_call_many, HandlerType::Slow),
            ("trace_filter", trace_filter, HandlerType::Slow),
            (
                "trace_rawTransaction",
                trace_raw_transaction,
                HandlerType::Slow
            ),
            (
                "trace_replayBlockTransactions",
                trace_replay_block_transactions,
                HandlerType::Slow
            ),
            (
                "trace_replayTransaction",
                trace_replay_transaction,
                HandlerType::Slow
            ),
            ("trace_transaction", trace_transaction, HandlerType::Slow),
        ]
    )
}

/// trace_block
fn trace_block(params: Params, node: &Arc<Node>) -> Result<Vec<TraceResults>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;

    // Default trace types for block tracing
    let trace_types = [TraceType::Trace, TraceType::StateDiff]
        .into_iter()
        .collect();

    // Get the block
    let block = node
        .get_block(block_number)?
        .ok_or_else(|| anyhow!("missing block: {block_number}"))?;

    // Get the parent block
    let parent = node
        .get_block(block.parent_hash())?
        .ok_or_else(|| anyhow!("missing parent block: {}", block.parent_hash()))?;

    // Start from parent block's state
    let mut state = node
        .consensus
        .read()
        .state()
        .at_root(parent.state_root_hash().into());

    let fork = state.forks.get(block.number()).clone();

    let mut traces = Vec::new();

    // Process each transaction
    for &txn_hash in block.transactions.iter() {
        let txn = node
            .get_transaction_by_hash(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;

        // Create inspector for tracing
        let config = TracingInspectorConfig::from_parity_config(&trace_types);
        let mut inspector = TracingInspector::new(config);
        let pre_state = PendingState::new(state.try_clone()?, fork.clone());

        // Apply the transaction
        let result = state.apply_transaction(txn, block.header, &mut inspector, true)?;

        // Build trace results
        if let TransactionApplyResult::Evm(result, ..) = result {
            let builder = inspector.into_parity_builder();
            let trace = builder.into_trace_results_with_state(&result, &trace_types, &pre_state)?;
            traces.push(trace);
        }
    }

    Ok(traces)
}

/// trace_call
fn trace_call(_params: Params, _node: &Arc<Node>) -> Result<()> {
    // TODO: disable_eip3607 for this call.
    Err(anyhow!("API method trace_call is not implemented yet"))
}

/// trace_callMany
fn trace_call_many(_params: Params, _node: &Arc<Node>) -> Result<()> {
    // TODO: disable_eip3607 for this call.
    Err(anyhow!("API method trace_callMany is not implemented yet"))
}

/// trace_filter
fn trace_filter(params: Params, node: &Arc<Node>) -> Result<Vec<TraceResults>> {
    #[derive(Debug, Deserialize)]
    struct TraceFilter {
        from_block: Option<BlockNumberOrTag>,
        to_block: Option<BlockNumberOrTag>,
        from_address: Option<Vec<Address>>,
        to_address: Option<Vec<Address>>,
        after: Option<u64>, // Offset
        count: Option<u64>, // Number of traces to return
    }

    let mut params = params.sequence();
    let filter: TraceFilter = params.next()?;

    // Default to latest block if not specified
    let from_block = filter.from_block.unwrap_or(BlockNumberOrTag::Earliest);
    let to_block = filter.to_block.unwrap_or(BlockNumberOrTag::Latest);

    // Resolve block numbers
    let start_block = node
        .resolve_block_number(from_block)?
        .ok_or_else(|| anyhow!("invalid from_block"))?;
    let end_block = node
        .resolve_block_number(to_block)?
        .ok_or_else(|| anyhow!("invalid to_block"))?;

    // Validate block range
    if start_block.number() > end_block.number() {
        return Err(anyhow!("invalid block range"));
    }

    // Default trace types for filtering
    let trace_types = [TraceType::Trace, TraceType::StateDiff]
        .into_iter()
        .collect();

    // Paging information
    let mut txns_skipped_count = 0;
    let mut txns_returned_count = 0;

    let mut all_traces = Vec::new();

    // Process each block in range
    'block_loop: for block_num in start_block.number()..=end_block.number() {
        let Some(block) = node.get_block(BlockNumberOrTag::Number(block_num))? else {
            continue;
        };

        // Skip empty blocks
        if block.transactions.is_empty() {
            continue;
        }

        let parent = node
            .get_block(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing parent block: {}", block.parent_hash()))?;

        let mut state = node
            .consensus
            .read()
            .state()
            .at_root(parent.state_root_hash().into());

        let fork = state.forks.get(block.number()).clone();

        // Process each transaction in the block
        for txn_hash in &block.transactions {
            let txn = match node.get_transaction_by_hash(*txn_hash)? {
                Some(tx) => tx,
                None => continue,
            };

            // Apply address filters
            let tx_from = txn.signer;
            let tx_to = txn.tx.clone().into_transaction().to_addr();

            if let Some(ref from_addrs) = filter.from_address
                && !from_addrs.contains(&tx_from)
            {
                continue;
            }

            if let Some(ref to_addrs) = filter.to_address {
                if let Some(to_addr) = tx_to {
                    if !to_addrs.contains(&to_addr) {
                        continue;
                    }
                } else {
                    // Skip if filtering by to_address and this is a contract creation
                    continue;
                }
            }

            if filter.after.is_some() && txns_skipped_count < filter.after.unwrap() {
                txns_skipped_count += 1;
                continue;
            }
            if filter.count.is_some() && txns_returned_count >= filter.count.unwrap() {
                break 'block_loop;
            }
            txns_returned_count += 1;

            // Create inspector and trace the transaction
            let config = TracingInspectorConfig::from_parity_config(&trace_types);
            let mut inspector = TracingInspector::new(config);
            let pending_state = PendingState::new(state.try_clone()?, fork.clone());

            let result = state.apply_transaction(txn, block.header, &mut inspector, true)?;

            // Only include EVM transaction traces
            if let TransactionApplyResult::Evm(result, ..) = result {
                let builder = inspector.into_parity_builder();
                let trace =
                    builder.into_trace_results_with_state(&result, &trace_types, &pending_state)?;
                all_traces.push(trace);
            }
        }
    }

    Ok(all_traces)
}

/// trace_rawTransaction
fn trace_raw_transaction(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method trace_rawTransaction is not implemented yet"
    ))
}

/// trace_replayBlockTransactions
fn trace_replay_block_transactions(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method trace_replayBlockTransactions is not implemented yet"
    ))
}

/// trace_replayTransaction
fn trace_replay_transaction(params: Params, node: &Arc<Node>) -> Result<TraceResults> {
    let mut params = params.sequence();
    let txn_hash: B256 = params.next()?;
    let txn_hash: Hash = txn_hash.into();
    let trace_types = params.next()?;

    let trace = Node::trace_evm_transaction(node, txn_hash, &trace_types)?;

    Ok(trace)
}

/// trace_transaction
fn trace_transaction(params: Params, node: &Arc<Node>) -> Result<TraceResults> {
    let mut params = params.sequence();
    let txn_hash: B256 = params.next()?;
    let txn_hash: Hash = txn_hash.into();

    // Default parity trace types for transaction tracing
    let trace_types = [TraceType::Trace, TraceType::VmTrace, TraceType::StateDiff]
        .into_iter()
        .collect();

    let trace = Node::trace_evm_transaction(node, txn_hash, &trace_types)?;

    Ok(trace)
}
