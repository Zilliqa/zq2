use std::sync::Arc;

use anyhow::{Result, anyhow};
use jsonrpsee::{RpcModule, types::Params};
use parking_lot::RwLock;
use sha3::{Digest, Keccak256};

use super::to_hex::ToHex;
use crate::{cfg::EnabledApi, node::Node};

pub fn rpc_module(
    node: Arc<RwLock<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<RwLock<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
        [("web3_clientVersion", client_version), ("web3_sha3", sha3)],
    )
}

fn client_version(_: Params, _: &Arc<RwLock<Node>>) -> Result<&'static str> {
    // Format: "<name>/<version>"
    Ok(concat!("zilliqa2/", env!("VERGEN_GIT_DESCRIBE")))
}

fn sha3(params: Params, _: &Arc<RwLock<Node>>) -> Result<String> {
    let data: String = params.one()?;
    let data = data
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let data = hex::decode(data)?;

    let hashed = Keccak256::digest(data);

    Ok(hashed.to_hex())
}
