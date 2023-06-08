use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("web3_clientVersion", client_version)])
}

fn client_version(_: Params, _: &Arc<Mutex<Node>>) -> Result<&'static str> {
    // Format: "<name>/<version>"
    Ok(concat!("zilliqa2/v", env!("CARGO_PKG_VERSION")))
}
