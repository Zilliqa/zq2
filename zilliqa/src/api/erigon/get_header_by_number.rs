use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::types::Params;

use super::super::types::eth;
use crate::{message::BlockNumber, node::Node};

pub(crate) fn get_header_by_number(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::Block>> {
    let block: BlockNumber = params.one()?;

    // Erigon headers are a subset of the full block response. We choose to just return the full block.
    let Some(ref block) = node.lock().unwrap().get_block_by_blocknum(block)? else {
        return Ok(None);
    };

    let miner = node
        .lock()
        .unwrap()
        .get_proposer_reward_address(block.header)?;
    Ok(Some(eth::Block::from_block(
        block,
        miner.unwrap_or_default(),
    )))
}
