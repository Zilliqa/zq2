use std::sync::Arc;

use anyhow::Result;
use jsonrpsee::{RpcModule, types::Params};
use parking_lot::RwLock;

use crate::{cfg::EnabledApi, node::Node};

pub fn rpc_module(
    node: Arc<RwLock<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<RwLock<Node>>> {
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
fn net_listening(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<bool> {
    Ok(true)
}

/// net_peerCount
fn net_peer_count(_: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let peer_count = node.read().get_peer_num();
    Ok(format!("0x{peer_count:x}"))
}

/// net_version
fn version(_: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    Ok(node.read().config.eth_chain_id.to_string())
}
