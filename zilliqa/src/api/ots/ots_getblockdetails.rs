use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::types::Params;

use crate::api::types::ots;
use crate::node::Node;

pub(crate) fn get_block_details(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<ots::BlockDetails>> {
    let block: u64 = params.one()?;

    let Some(ref block) = node.lock().unwrap().get_block_by_number(block)? else {
        return Ok(None);
    };
    let miner = node
        .lock()
        .unwrap()
        .get_proposer_reward_address(block.header)?;

    Ok(Some(ots::BlockDetails::from_block(
        block,
        miner.unwrap_or_default(),
    )))
}
