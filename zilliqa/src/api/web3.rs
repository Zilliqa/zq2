use std::sync::{Arc, Mutex};
use crate::api::print_type_of;

use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use sha3::{Digest, Keccak256};

use super::to_hex::ToHex;
use crate::node::Node;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [("web3_clientVersion", client_version), ("web3_sha3", sha3)],
    )
}

fn client_version(_: Params, _: &Arc<Mutex<Node>>) -> Result<&'static str> {
    // Format: "<name>/<version>"
    Ok(concat!("zilliqa2/v", env!("CARGO_PKG_VERSION")))
}

fn sha3(params: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    let data: String = params.one()?;
    let data = data
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let data = hex::decode(data)?;

    let hashed = Keccak256::digest(data);

    Ok(hashed.to_hex())
}
