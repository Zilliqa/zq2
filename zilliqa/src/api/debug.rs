//! A debugging API.

#![allow(unused_imports)]
use crate::block_store::BlockStoreStatus;
use crate::node::Node;
use crate::range_map::RangeMap;
use anyhow::{anyhow, Result};
use jsonrpsee::{
    core::StringError,
    types::{error::ErrorObjectOwned, params::ParamsSequence, Params},
    PendingSubscriptionSink, RpcModule, SubscriptionMessage,
};
use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::trace;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("zdebug_fish", fish),
            ("zdebug_echo", echo),
            ("zdebug_blockstore", blocks),
            ("zdebug_forget", forget),
            ("zdebug_request", request)
        ]
    )
}

fn echo(params: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("echo: params: {:?}", params);
    let mut params = params.sequence();
    let msg: String = params.next()?;
    Ok(msg)
}

fn fish(params: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("fish: params: {:?}", params);
    let mut params = params.sequence();
    let msg: String = params.next()?;
    Ok(msg)
}

fn blocks(_params: Params, node: &Arc<Mutex<Node>>) -> Result<BlockStoreStatus> {
    trace!("blocks");
    let mut node = node.lock().unwrap();
    Ok(BlockStoreStatus::new(&mut node.consensus.block_store)?)
}

fn forget(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let from: u64 = params.next()?;
    let to: u64 = params.next()?;
    let mut node = node.lock().unwrap();
    trace!("Forget blocks from {from} to {to}");
    node.consensus.block_store.forget_block_range(Range {
        start: from,
        end: to + 1,
    })?;
    Ok("done".to_string())
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
