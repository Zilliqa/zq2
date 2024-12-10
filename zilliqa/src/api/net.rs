use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
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
fn net_peer_count(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();
    let num_peers = node.get_peer_num();
    Ok(num_peers.to_string())
}

/// net_version
fn version(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().config.eth_chain_id.to_string())
}
