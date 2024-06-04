use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use hyper::ext::HashMap;
use jsonrpsee::{types::Params, RpcModule};

use super::types::eth;
use crate::{message::BlockNumber, node::Node};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("erigon_getHeaderByNumber", get_header_by_number),
            ("txpool_content", txpool_content)
        ]
    )
}

fn get_header_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::Block>> {
    let block: BlockNumber = params.one()?;

    // Erigon headers are a subset of the full block response. We choose to just return the full block.
    let Some(ref block) = node.lock().unwrap().get_block_by_blocknum(block)? else {
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

fn txpool_content(_params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::TxPoolContent>> {

    let content = node.lock().unwrap().txpool_content();

    let result = eth::TxPoolContent { pending: Vec::HashMap(), queued: Vec::HashMap()};



    for item in content.pending {

    }



    Ok(Some(eth::TxPoolContent {
        pending: HashMap::new(),
        queued: HashMap::new(),
    }))
}
