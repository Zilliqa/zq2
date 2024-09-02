//! A debugging API.

#![allow(unused_imports)]
use crate::block_store::BlockStoreStatus;
use crate::node::Node;
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
    let mut module =
        super::declare_module!(node, [("zdebug_echo", echo), ("zdebug_blockstore", blocks)]);
    module
}

fn echo(params: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("echo: params: {:?}", params);
    let mut params = params.sequence();
    let msg: String = params.next()?;
    Ok(msg)
}

fn blocks(params: Params, node: &Arc<Mutex<Node>>) -> Result<BlockStoreStatus> {
    trace!("blocks");
    let mut node = node.lock().unwrap();
    Ok(BlockStoreStatus::new(&mut node.consensus.block_store)?)
}
