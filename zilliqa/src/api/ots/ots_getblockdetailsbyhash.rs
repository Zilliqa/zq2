use std::sync::{Arc, Mutex};

use crate::api::types::ots;
use anyhow::Result;
use jsonrpsee::types::Params;

use crate::{crypto::Hash, node::Node};
use alloy_primitives::B256;

pub(crate) fn get_block_details_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<ots::BlockDetails>> {
    let block_hash: B256 = params.one()?;

    let Some(ref block) = node.lock().unwrap().get_block_by_hash(Hash(block_hash.0))? else {
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
