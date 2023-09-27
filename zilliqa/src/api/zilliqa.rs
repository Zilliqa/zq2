//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::{panic::AssertUnwindSafe, sync::Arc};
use tokio::sync::Mutex;

use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::{H160, U256};
use serde_json::json;

use crate::{message::BlockNumber, node::Node, state::Address};

use super::types::zilliqa;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("GetBalance", get_balance),
            ("GetCurrentMiniEpoch", get_current_mini_epoch),
            ("GetLatestTxBlock", get_latest_tx_block),
            ("GetMinimumGasPrice", get_minimum_gas_price),
            ("GetNetworkId", get_network_id),
            ("GetVersion", get_git_commit),
        ],
    )
}

async fn get_balance(params: Params<'_>, node: &Arc<Mutex<Node>>) -> Result<serde_json::Value> {
    let address: H160 = params.one()?;

    let node = node.lock().await;

    let balance = node
        .get_native_balance(Address(address), BlockNumber::Latest)
        .await?;
    // We need to scale the balance from units of (10^-18) ZIL to (10^-12) ZIL. The value is truncated in this process.
    let balance = balance / U256::from(10).pow(U256::from(6));
    let balance = balance.to_string();
    let nonce = node
        .get_account(Address(address), BlockNumber::Latest)
        .await?
        .nonce;

    Ok(json!({"balance": balance, "nonce": nonce}))
}

async fn get_current_mini_epoch(_: Params<'_>, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().await.view().to_string())
}

async fn get_latest_tx_block(_: Params<'_>, node: &Arc<Mutex<Node>>) -> Result<zilliqa::TxBlock> {
    let node = node.lock().await;
    let block = node
        .get_block_by_number(BlockNumber::Latest)
        .await?
        .ok_or_else(|| anyhow!("no blocks"))?;

    Ok((&block).into())
}

async fn get_minimum_gas_price(_: Params<'_>, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().await.get_gas_price().to_string())
}

fn network_id(eth_chain_id: u64) -> u64 {
    // We fix the convention the Zilliqa network ID is equal to the Ethereum chain ID minus 0x8000. This is true for
    // all current Zilliqa networks.
    eth_chain_id - 0x8000
}

async fn get_network_id(_: Params<'_>, node: &Arc<Mutex<Node>>) -> Result<String> {
    let network_id = network_id(node.lock().await.config.eth_chain_id);
    Ok(network_id.to_string())
}

async fn get_git_commit(_: Params<'_>, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(env!("VERGEN_GIT_DESCRIBE").to_string())
}
