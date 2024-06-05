use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use super::types::eth;
use crate::{api::types::eth::Transaction, message::BlockNumber, node::Node};

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

    let mut result = eth::TxPoolContent {
        pending: HashMap::new(),
        queued: HashMap::new(),
    };

    for item in content.pending {
        let txns = result.pending.entry(item.signer).or_default();
        txns.insert(item.tx.nonce().unwrap(), Transaction::new(item, None));
    }

    for item in content.queued {
        let txns = result.queued.entry(item.signer).or_default();
        txns.insert(item.tx.nonce().unwrap(), Transaction::new(item, None));
    }

    Ok(Some(result))
}
