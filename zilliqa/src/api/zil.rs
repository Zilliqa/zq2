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

use super::{
    to_hex::ToHex,
    types::zil::{self, BlockchainInfo, ShardingStructure},
};
use crate::{
    api::types::zil::{CreateTransactionResponse, GetTxResponse},
    crypto::Hash,
    message::BlockNumber,
    node::Node,
    schnorr,
    state::{Contract, ScillaValue},
    transaction::{
        ScillaGas, SignedTransaction, TxZilliqa, VerifiedTransaction, ZilAmount,
        EVM_GAS_PER_SCILLA_GAS,
    },
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("CreateTransaction", create_transaction),
            (
                "GetContractAddressFromTransactionID",
                get_contract_address_from_transaction_id
            ),
            ("GetBlockchainInfo", get_blockchain_info),
            ("GetNumTxBlocks", get_num_tx_blocks),
            ("GetSmartContractState", get_smart_contract_state),
            ("GetSmartContractCode", get_smart_contract_code),
            ("GetSmartContractInit", get_smart_contract_init),
            ("GetTransaction", get_transaction),
            ("GetBalance", get_balance),
            ("GetCurrentMiniEpoch", get_current_mini_epoch),
            ("GetLatestTxBlock", get_latest_tx_block),
            ("GetMinimumGasPrice", get_minimum_gas_price),
            ("GetNetworkId", get_network_id),
            ("GetVersion", get_version),
            ("GetTransactionsForTxBlock", get_transactions_for_tx_block),
            ("GetTxBlock", |p, n| get_tx_block(p, n, false)),
            ("GetTxBlockVerbose", |p, n| get_tx_block(p, n, true)),
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
    amount: ZilAmount,
    pub_key: String,
    #[serde(deserialize_with = "from_str")]
    gas_price: ZilAmount,
    #[serde(deserialize_with = "from_str")]
    gas_limit: ScillaGas,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    data: Option<String>,
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

    // TODO: Perform some initial validation of the transaction

    let transaction = SignedTransaction::Zilliqa {
        tx: TxZilliqa {
            chain_id: chain_id as u16,
            nonce: transaction.nonce,
            gas_price: transaction.gas_price,
            gas_limit: transaction.gas_limit,
            to_addr: transaction.to_addr,
            amount: transaction.amount,
            code: transaction.code.unwrap_or_default(),
            data: transaction.data.unwrap_or_default(),
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

fn get_contract_address_from_transaction_id(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<String> {
    let hash: H256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let receipt = node
        .lock()
        .unwrap()
        .get_transaction_receipt(hash)?
        .ok_or_else(|| anyhow!("Txn Hash not Present"))?;

    let contract_address = receipt
        .contract_address
        .ok_or_else(|| anyhow!("ID is not a contract txn"))?;

    Ok(contract_address.to_hex_no_prefix())
}

fn get_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<GetTxResponse>> {
    let hash: H256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let tx = get_scilla_transaction_inner(hash, &node.lock().unwrap())?
        .ok_or_else(|| anyhow!("Txn Hash not Present"))?;
    let receipt = node
        .lock()
        .unwrap()
        .get_transaction_receipt(hash)?
        .ok_or_else(|| anyhow!("Txn Hash not Present"))?;
    let block = node
        .lock()
        .unwrap()
        .get_block_by_hash(receipt.block_hash)?
        .ok_or_else(|| anyhow!("block does not exist"))?;

    Ok(GetTxResponse::new(tx, receipt, block.number()))
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

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
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

fn get_minimum_gas_price(_: Params, node: &Arc<Mutex<Node>>) -> Result<ZilAmount> {
    let price = node.lock().unwrap().get_gas_price();
    // `price` is the cost per unit of [EvmGas]. This API should return the cost per unit of [ScillaGas].
    let price = price * (EVM_GAS_PER_SCILLA_GAS as u128);

    Ok(ZilAmount::from_amount(price))
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

fn get_blockchain_info(_: Params, node: &Arc<Mutex<Node>>) -> Result<BlockchainInfo> {
    let node = node.lock().unwrap();

    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;

    Ok(BlockchainInfo {
        num_peers: 0,
        num_tx_blocks,
        num_ds_blocks,
        num_transactions: 0,
        transaction_rate: 0.0,
        tx_block_rate: 0.0,
        ds_block_rate: 0.0,
        current_mini_epoch: num_tx_blocks,
        current_ds_epoch: num_ds_blocks,
        num_txns_ds_epoch: 0,
        num_txns_tx_epoch: 0,
        sharding_structure: ShardingStructure { num_peers: vec![0] },
    })
}

fn get_num_tx_blocks(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();

    Ok(node.get_chain_tip().to_string())
}

fn get_smart_contract_state(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let smart_contract_address: H160 = params.one()?;
    let node = node.lock().unwrap();

    // First get the account and check that its a scilla account
    let account = node.get_account(smart_contract_address, BlockNumber::Latest)?;

    let mut result = json!({
        "_balance": ZilAmount::from_amount(account.balance).to_string(),
    });

    fn convert(value: ScillaValue) -> Result<Value> {
        let value = match value {
            ScillaValue::Bytes(b) => serde_json::from_slice(&b)?,
            ScillaValue::Map(m) => Value::Object(
                m.into_iter()
                    .map(|(k, v)| Ok((serde_json::from_str(&k)?, convert(v)?)))
                    .collect::<Result<_>>()?,
            ),
        };
        Ok(value)
    }

    if let Contract::Scilla { storage, .. } = account.contract {
        for (k, (v, _)) in storage {
            result[k] = convert(v)?;
        }
    }

    Ok(result)
}

fn get_smart_contract_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let smart_contract_address: H160 = params.one()?;
    let node = node.lock().unwrap();
    let account = node.get_account(smart_contract_address, BlockNumber::Latest)?;

    if let Contract::Scilla { code, .. } = account.contract {
        Ok(json!({ "code": code }))
    } else {
        Err(anyhow!("Address not contract address"))
    }
}

fn get_smart_contract_init(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let smart_contract_address: H160 = params.one()?;
    let node = node.lock().unwrap();
    let account = node.get_account(smart_contract_address, BlockNumber::Latest)?;

    if let Contract::Scilla { init_data, .. } = account.contract {
        Ok(serde_json::from_str(&init_data)?)
    } else {
        Err(anyhow!("Address not contract address"))
    }
}

fn get_transactions_for_tx_block(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Vec<Vec<String>>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let node = node.lock().unwrap();
    let Some(block) = node.get_block_by_number(block_number)? else {
        return Err(anyhow!("Tx Block does not exist"));
    };
    if block.transactions.is_empty() {
        return Err(anyhow!("TxBlock has no transactions"));
    }

    Ok(vec![block
        .transactions
        .into_iter()
        .map(|h| H256(h.0).to_hex_no_prefix())
        .collect()])
}

pub const TRANSACTIONS_PER_PAGE: usize = 2500;
pub const TX_BLOCKS_PER_DS_BLOCK: u64 = 100;

fn get_tx_block(
    params: Params,
    node: &Arc<Mutex<Node>>,
    verbose: bool,
) -> Result<Option<zil::TxBlock>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let node = node.lock().unwrap();
    let Some(block) = node.get_block_by_number(block_number)? else {
        return Ok(None);
    };
    let mut block: zil::TxBlock = (&block).into();

    if verbose {
        block.header.committee_hash = Some(H256::zero());
        block.body.cosig_bitmap_1 = vec![true; 8];
        block.body.cosig_bitmap_2 = vec![true; 8];
        let mut scalar = [0; 32];
        scalar[31] = 1;
        block.body.cosig_1 = Some(schnorr::Signature::from_scalars(scalar, scalar).unwrap());
    }

    Ok(Some(block))
}
