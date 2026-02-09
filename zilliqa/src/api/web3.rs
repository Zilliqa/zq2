use std::sync::Arc;

use alloy::hex;
use anyhow::{Result, anyhow};
use jsonrpsee::{RpcModule, types::Params};
use sha3::{Digest, Keccak256};

use super::to_hex::ToHex;
use crate::{
    api::{
        HandlerType, disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook,
        rpc_base_attributes,
    },
    cfg::EnabledApi,
    node::Node,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("web3_clientVersion", client_version, HandlerType::Fast),
            ("web3_sha3", sha3, HandlerType::Fast)
        ],
    )
}

fn client_version(_: Params, _: &Arc<Node>) -> Result<&'static str> {
    // Format: "<name>/<version>"
    Ok(concat!("zilliqa2/", env!("VERGEN_GIT_DESCRIBE")))
}

fn sha3(params: Params, _: &Arc<Node>) -> Result<String> {
    let data: String = params.one()?;
    let data = data
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let data = hex::decode(data)?;

    let hashed = Keccak256::digest(data);

    Ok(hashed.to_hex())
}
