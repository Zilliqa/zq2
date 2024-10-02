#![cfg(feature = "debug_api")]
#![allow(unused_imports)]
use std::{
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{anyhow, Result};
use jsonrpsee::{
    core::StringError,
    types::{error::ErrorObjectOwned, params::ParamsSequence, Params},
    PendingSubscriptionSink, RpcModule, SubscriptionMessage,
};
use serde::{Deserialize, Serialize};
use tracing::trace;

use super::to_hex::ToHex;
use crate::{
    block_store::BlockStoreStatus, message::BlockStrategy, node::Node, range_map::RangeMap,
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("zdbg_echo", echo),
            ("zdbg_blockstore", blocks),
            ("zdbg_request", request),
            ("zdbg_checkpoint", checkpoint)
        ]
    )
}

fn checkpoint(_params: Params, node: &Arc<Mutex<Node>>) -> Result<(String, String, String)> {
    let mut node = node.lock().unwrap();
    let block = node.number();
    let (file_name, hash) = node.consensus.checkpoint_at(block)?;
    // Horrid, but better than making changes all over the code just to support this.
    Ok((file_name, hash, block.to_hex()))
}

fn echo(params: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("echo: params: {:?}", params);
    let mut params = params.sequence();
    let msg: String = params.next()?;
    Ok(msg)
}

fn blocks(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<(BlockStoreStatus, Option<Vec<BlockStrategy>>, RangeMap)> {
    trace!("blocks");
    let mut node = node.lock().unwrap();
    Ok((
        BlockStoreStatus::new(&mut node.consensus.block_store)?,
        node.consensus.block_store.availability()?,
        node.consensus.block_store.summarise_buffered(),
    ))
}

fn request(params: Params, node: &Arc<Mutex<Node>>) -> Result<bool> {
    let mut params = params.sequence();
    let from: u64 = params.next()?;
    let to: u64 = params.next()?;
    let mut node = node.lock().unwrap();
    trace!("Request blocks from {from} to {to}");
    let result = node
        .consensus
        .block_store
        .request_blocks(&RangeMap::from_closed_interval(from, to))?;
    Ok(result)
}
