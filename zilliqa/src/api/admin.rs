//! An administrative API

use std::sync::{Arc, Mutex};

use alloy::eips::BlockNumberOrTag;
use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use serde::{Deserialize, Serialize};

use crate::{api::to_hex::ToHex, node::Node};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("admin_generateCheckpoint", checkpoint)])
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckpointResponse {
    /// File name - when this file exists, the checkpoint is done.
    file_name: String,
    /// Checkpoint hash
    hash: String,
    /// Block number as hex.
    block: String,
}

fn checkpoint(params: Params, node: &Arc<Mutex<Node>>) -> Result<CheckpointResponse> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let mut node = node.lock().unwrap();
    let block = node
        .get_block(block_number)?
        .ok_or(anyhow!("Block {block_number} does not exist"))?;

    let (file_name, hash) = node.consensus.checkpoint_at(block.number())?;
    Ok(CheckpointResponse {
        file_name,
        hash,
        block: block.number().to_hex(),
    })
}
