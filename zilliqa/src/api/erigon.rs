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
    let header = node
        .lock()
        .unwrap()
        .get_block_by_blocknum(block)?
        .as_ref()
        .map(eth::Block::from);

    Ok(header)
}
