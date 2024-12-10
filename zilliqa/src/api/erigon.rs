use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use super::types::eth;
use crate::node::Node;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("erigon_blockNumber", block_number),
            ("erigon_forks", forks),
            ("erigon_getBlockByTimestamp", get_block_by_timestamp),
            (
                "erigon_getBlockReceiptsByBlockHash",
                get_block_receipts_by_block_hash
            ),
            ("erigon_getHeaderByHash", get_header_by_hash),
            ("erigon_getHeaderByNumber", get_header_by_number),
            ("erigon_getLatestLogs", get_latest_logs),
            ("erigon_getLogsByHash", get_logs_by_hash),
        ]
    )
}

/// erigon_blockNumber
fn block_number(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// erigon_forks
fn forks(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// erigon_getBlockByTimestamp
fn get_block_by_timestamp(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// erigon_getBlockReceiptsByBlockHash
fn get_block_receipts_by_block_hash(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// erigon_getHeaderByHash
fn get_header_by_hash(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// erigon_getHeaderByNumber
fn get_header_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::Block>> {
    let block: u64 = params.one()?;

    // Erigon headers are a subset of the full block response. We choose to just return the full block.
    let Some(ref block) = node.lock().unwrap().get_block(block)? else {
        return Ok(None);
    };

    let miner = node
        .lock()
        .unwrap()
        .get_proposer_reward_address(block.header)?;

    let block_gas_limit = node.lock().unwrap().config.consensus.eth_block_gas_limit;
    Ok(Some(eth::Block::from_block(
        block,
        miner.unwrap_or_default(),
        block_gas_limit,
    )))
}

/// erigon_getLatestLogs
fn get_latest_logs(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}

/// erigon_getLogsByHash
fn get_logs_by_hash(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet");
}
