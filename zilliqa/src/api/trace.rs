use std::sync::{Arc, Mutex};

use alloy::{primitives::B256, rpc::types::trace::parity::TraceResults};
use anyhow::{anyhow, Result};
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
            ("trace_block", trace_block),
            ("trace_call", trace_call),
            ("trace_callMany", trace_call_many),
            ("trace_filter", trace_filter),
            ("trace_rawTransaction", trace_raw_transaction),
            (
                "trace_replayBlockTransactions",
                trace_replay_block_transactions
            ),
            ("trace_replayTransaction", trace_replay_transaction),
            ("trace_transaction", trace_transaction),
        ]
    )
}

/// trace_block
fn trace_block(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// trace_call
fn trace_call(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method trace_call is not implemented yet"))
}

/// trace_callMany
fn trace_call_many(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method trace_callMany is not implemented yet"))
}

/// trace_filter
fn trace_filter(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// trace_rawTransaction
fn trace_raw_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method trace_rawTransaction is not implemented yet"
    ))
}

/// trace_replayBlockTransactions
fn trace_replay_block_transactions(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method trace_replayBlockTransactions is not implemented yet"
    ))
}

/// trace_replayTransaction
fn trace_replay_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<TraceResults> {
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

/// trace_transaction
fn trace_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}
