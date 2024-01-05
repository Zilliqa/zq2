use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use super::types::eth;
use crate::{message::BlockNumber, node::Node};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("erigon_getHeaderByNumber", get_header_by_number)])
}

fn get_header_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::Block>> {
    let block: BlockNumber = params.one()?;

    // Erigon headers are a subset of the full block response. We choose to just return the full block.
    let Some(ref header) = node.lock().unwrap().get_block_by_blocknum(block)? else {
        return Ok(None);
    };

    let miner = node.lock().unwrap().get_proposer_reward_address(header)?;
    Ok(Some(eth::Block::from_block(
        header,
        miner.unwrap_or_default(),
    )))
}
