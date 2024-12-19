use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use crate::{cfg::EnabledApi, node::Node};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("net_listening", net_listening),
            ("net_peerCount", net_peer_count),
            ("net_version", version),
        ]
    )
}

/// net_listening
fn net_listening(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<bool> {
    Ok(true)
}

/// net_peerCount
fn net_peer_count(_: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok("0x0".to_string())
}

/// net_version
fn version(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().config.eth_chain_id.to_string())
}
