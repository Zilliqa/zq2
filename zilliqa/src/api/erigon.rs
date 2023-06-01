use std::sync::{Arc, Mutex};

use anyhow::Result;
use anyhow::anyhow;

use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

use super::types::EthBlock;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("erigon_getHeaderByNumber", get_header_by_number)])
}

fn get_header_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<EthBlock>> {
    let block: u64 = params.one()?;

    // Erigon headers are a subset of the full block response. We choose to just return the full block.
    let header = node
        .lock()
        .unwrap()
        .get_block_by_view(block)
        .map(EthBlock::from);

    Ok(header)
}
