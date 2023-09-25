use std::{panic::AssertUnwindSafe, sync::Arc};
use tokio::sync::Mutex;

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("net_version", version)])
}

async fn version(_: Params<'_>, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().await.config.eth_chain_id.to_string())
}
