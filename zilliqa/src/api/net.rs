use std::sync::Arc;

use anyhow::Result;
use jsonrpsee::{RpcModule, types::Params};

use crate::{
    api::{
        disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook, rpc_base_attributes,
    },
    cfg::EnabledApi,
    node::Node,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
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
fn net_listening(_params: Params, _node: &Arc<Node>) -> Result<bool> {
    Ok(true)
}

/// net_peerCount
fn net_peer_count(_: Params, node: &Arc<Node>) -> Result<String> {
    let peer_count = node.get_peer_num();
    Ok(format!("0x{peer_count:x}"))
}

/// net_version
fn version(_: Params, node: &Arc<Node>) -> Result<String> {
    Ok(node.config.eth_chain_id.to_string())
}
