//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::H160;
use serde_json::json;

use crate::{message::BlockNumber, node::Node, state::Address};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("GetBalance", get_balance),
            ("GetCurrentMiniEpoch", get_current_mini_epoch),
            ("GetMinimumGasPrice", get_minimum_gas_price),
            ("GetVersion", get_git_commit),
        ],
    )
}

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<serde_json::Value> {
    let address: H160 = params.one()?;

    let node = node.lock().unwrap();

    let balance = node
        .get_native_balance(Address(address), BlockNumber::Latest)?
        .to_string();
    let nonce = node
        .get_account(Address(address), BlockNumber::Latest)?
        .nonce;

    Ok(json!({"balance": balance, "nonce": nonce}))
}

fn get_current_mini_epoch(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().view().to_string())
}

fn get_minimum_gas_price(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().get_gas_price().to_string())
}

fn get_git_commit(_: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(env!("VERGEN_GIT_DESCRIBE").to_string())
}
