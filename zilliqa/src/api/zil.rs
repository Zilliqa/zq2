//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::{
    fmt::Display,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::{H160, H256};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use super::types::zil;
use crate::{
    api::types::zil::{CreateTransactionResponse, GetTxResponse},
    crypto::Hash,
    message::BlockNumber,
    node::Node,
    schnorr,
    transaction::{SignedTransaction, TxZilliqa, VerifiedTransaction},
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("CreateTransaction", create_transaction),
            ("GetSmartContractState", get_smart_contract_state),
            ("GetTransaction", get_transaction),
            ("GetBalance", get_balance),
            ("GetCurrentMiniEpoch", get_current_mini_epoch),
            ("GetLatestTxBlock", get_latest_tx_block),
            ("GetMinimumGasPrice", get_minimum_gas_price),
            ("GetNetworkId", get_network_id),
            ("GetVersion", get_version),
        ],
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionParams {
    version: u32,
    nonce: u64,
    to_addr: H160,
    #[serde(deserialize_with = "from_str")]
    amount: u128,
    pub_key: String,
    #[serde(deserialize_with = "from_str")]
    gas_price: u128,
    #[serde(deserialize_with = "from_str")]
    gas_limit: u64,
    #[serde(default)]
    code: String,
    #[serde(default)]
    data: String,
    signature: String,
}

fn from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

fn create_transaction(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<CreateTransactionResponse> {
    let transaction: TransactionParams = params.one()?;
    let mut node = node.lock().unwrap();

    let version = transaction.version & 0xffff;
    let chain_id = transaction.version >> 16;

    if (chain_id as u64) != (node.config.eth_chain_id - 0x8000) {
        return Err(anyhow!(
            "unexpected chain ID, expected: {}, got: {chain_id}",
            node.config.eth_chain_id - 0x8000
        ));
    }

    if version != 1 {
        return Err(anyhow!("unexpected version, expected: 1, got: {version}"));
    }

    let key = hex::decode(transaction.pub_key)?;

    let key = schnorr::PublicKey::from_sec1_bytes(&key)?;
    let sig = schnorr::Signature::from_str(&transaction.signature)?;

    let transaction = SignedTransaction::Zilliqa {
        tx: TxZilliqa {
            chain_id: chain_id as u16,
            nonce: transaction.nonce,
            gas_price: transaction.gas_price,
            gas_limit: transaction.gas_limit,
            to_addr: transaction.to_addr,
            amount: transaction.amount,
            code: transaction.code,
            data: transaction.data,
        },
        key,
        sig,
    };

    let transaction_hash = node.create_transaction(transaction.clone())?;

    let response = CreateTransactionResponse {
        contract_address: None,
        info: "Txn processed".to_string(),
        tran_id: transaction_hash.0.into(),
    };

    Ok(response)
}

fn get_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<GetTxResponse>> {
    let hash: H256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let tx = get_scilla_transaction_inner(hash, &node.lock().unwrap())?;
    let receipt = node.lock().unwrap().get_transaction_receipt(hash)?;

    // Note: the scilla api expects an err json rpc response if the transaction is not found
    // Canonical example:
    //     "error": {
    //     "code": -20,
    //     "data": null,
    //     "message": "Txn Hash not Present"
    // },
    let receipt = receipt.ok_or_else(|| anyhow!("Txn Hash not Present"))?;
    let tx = tx.ok_or_else(|| anyhow!("Txn Hash not Present"))?;

    Ok(GetTxResponse::new(tx, receipt))
}

pub(super) fn get_scilla_transaction_inner(
    hash: Hash,
    node: &MutexGuard<Node>,
) -> Result<Option<VerifiedTransaction>> {
    let Some(tx) = node.get_transaction_by_hash(hash)? else {
        return Ok(None);
    };

    match tx.tx {
        SignedTransaction::Zilliqa { .. } => Ok(Some(tx)),
        _ => Ok(None),
    }
}

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<serde_json::Value> {
    let address: H160 = params.one()?;

    let node = node.lock().unwrap();

    let balance = node.get_native_balance(address, BlockNumber::Latest)?;
    // We need to scale the balance from units of (10^-18) ZIL to (10^-12) ZIL. The value is truncated in this process.
    let balance = balance / 10u128.pow(6);
    let balance = balance.to_string();
    let nonce = node.get_account(address, BlockNumber::Latest)?.nonce;

    Ok(json!({"balance": balance, "nonce": nonce}))
}

fn get_current_mini_epoch(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().number().to_string())
}

fn get_latest_tx_block(_: Params, node: &Arc<Mutex<Node>>) -> Result<zil::TxBlock> {
    let node = node.lock().unwrap();
    let block = node
        .get_block_by_number(node.get_number(BlockNumber::Latest))?
        .ok_or_else(|| anyhow!("no blocks"))?;

    Ok((&block).into())
}

fn get_minimum_gas_price(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let price = node.lock().unwrap().get_gas_price();
    // We need to scale the balance from units of (10^-18) ZIL to (10^-12) ZIL. The value is truncated in this process.
    let price = price / 10u128.pow(6);

    Ok(price.to_string())
}

fn network_id(eth_chain_id: u64) -> u64 {
    // We fix the convention the Zilliqa network ID is equal to the Ethereum chain ID minus 0x8000. This is true for
    // all current Zilliqa networks.
    eth_chain_id - 0x8000
}

fn get_network_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let network_id = network_id(node.lock().unwrap().config.eth_chain_id);
    Ok(network_id.to_string())
}

fn get_version(_: Params, _: &Arc<Mutex<Node>>) -> Result<Value> {
    let commit = env!("VERGEN_GIT_SHA");
    let version = env!("VERGEN_GIT_DESCRIBE");
    Ok(json!({
        "Commit": commit,
        "Version": version,
    }))
}

fn get_smart_contract_state(params: Params, node: &Arc<Mutex<Node>>) -> Result<serde_json::Value> {
    let smart_contract_address: H160 = params.one()?;
    let node = node.lock().unwrap();

    // First get the account and check that its a scilla account
    let _account = node.get_account(smart_contract_address, BlockNumber::Latest)?;
    let balance = node.get_native_balance(smart_contract_address, BlockNumber::Latest)?;

    let mut return_json = serde_json::Value::Object(Default::default());
    return_json["_balance"] = serde_json::Value::String(balance.to_string());

    Ok(return_json)
}
