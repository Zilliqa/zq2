//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::{
    fmt::Display,
    str::FromStr,
    sync::{Arc, Mutex},
};

use alloy::{
    consensus::SignableTransaction,
    eips::BlockId,
    primitives::{Address, B256},
};
use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use super::{
    to_hex::ToHex,
    types::zil::{
        self, BlockchainInfo, DSBlock, DSBlockHeaderVerbose, DSBlockListing, DSBlockListingResult,
        DSBlockRateResult, DSBlockVerbose, GetCurrentDSCommResult, SWInfo, ShardingStructure,
        SmartContract, TXBlockRateResult, TransactionBody, TxBlockListing, TxBlockListingResult,
        TxnBodiesForTxBlockExResponse, TxnsForTxBlockExResponse,
    },
};
use crate::{
    api::types::zil::{CreateTransactionResponse, GetTxResponse, RPCErrorCode},
    crypto::Hash,
    exec::zil_contract_address,
    node::Node,
    schnorr,
    scilla::split_storage_key,
    state::{Code, ScillaTypedVariable},
    time::SystemTime,
    transaction::{ScillaGas, SignedTransaction, TxZilliqa, ZilAmount, EVM_GAS_PER_SCILLA_GAS},
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
            ("GetSmartContracts", get_smart_contracts),
            ("GetDSBlock", get_ds_block),
            ("GetDSBlockVerbose", get_ds_block_verbose),
            ("GetLatestDSBlock", get_latest_ds_block),
            ("GetCurrentDSComm", get_current_ds_comm),
            ("GetCurrentDSEpoch", get_current_ds_epoch),
            ("DSBlockListing", ds_block_listing),
            ("GetDSBlockRate", get_ds_block_rate),
            ("GetTxBlockRate", get_tx_block_rate),
            ("TxBlockListing", tx_block_listing),
            ("GetNumPeers", get_num_peers),
            ("GetTransactionRate", get_tx_rate),
            (
                "GetTransactionsForTxBlockEx",
                get_transactions_for_tx_block_ex
            ),
            ("GetTxnBodiesForTxBlockEx", get_txn_bodies_for_tx_block_ex),
        ],
    )
}

#[derive(Deserialize)]
#[serde(transparent)]
struct ZilAddress {
    #[serde(deserialize_with = "deserialize_zil_address")]
    inner: Address,
}

impl From<ZilAddress> for Address {
    fn from(value: ZilAddress) -> Self {
        value.inner
    }
}

fn deserialize_zil_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as E;

    let s = String::deserialize(deserializer)?;

    bech32::decode(&s).map_or_else(
        |_| s.parse().map_err(E::custom),
        |(hrp, data)| {
            if hrp.as_str() == "zil" {
                (&data[..]).try_into().map_err(E::custom)
            } else {
                Err(E::custom("Invalid HRP, expected 'zil'"))
            }
        },
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionParams {
    version: u32,
    nonce: u64,
    to_addr: Address,
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

    if (chain_id as u64) != (node.chain_id.zil()) {
        return Err(anyhow!(
            "unexpected chain ID, expected: {}, got: {chain_id}",
            node.chain_id.zil()
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
    let hash: B256 = params.one()?;
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

fn get_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<GetTxResponse> {
    let jsonrpc_error_data: Option<String> = None;
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let tx = node
        .lock()
        .unwrap()
        .get_transaction_by_hash(hash)?
        .ok_or_else(|| {
            jsonrpsee::types::ErrorObject::owned(
                RPCErrorCode::RpcDatabaseError as i32,
                "Txn Hash not Present".to_string(),
                jsonrpc_error_data.clone(),
            )
        })?;
    let receipt = node
        .lock()
        .unwrap()
        .get_transaction_receipt(hash)?
        .ok_or_else(|| {
            jsonrpsee::types::ErrorObject::owned(
                RPCErrorCode::RpcDatabaseError as i32,
                "Txn Hash not Present".to_string(),
                jsonrpc_error_data.clone(),
            )
        })?;
    let block = node
        .lock()
        .unwrap()
        .get_block(receipt.block_hash)?
        .ok_or_else(|| anyhow!("block does not exist"))?;

    GetTxResponse::new(tx, receipt, block.number())
}

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get latest block!"))?;

    let state = node.get_state(&block)?;

    if !state.has_account(address)? {
        return Err(jsonrpsee::types::ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            "Account is not created",
            None::<()>,
        )
        .into());
    }

    let account = state.get_account(address)?;

    // We need to scale the balance from units of (10^-18) ZIL to (10^-12) ZIL. The value is truncated in this process.
    let balance = account.balance / 10u128.pow(6);

    Ok(json!({"balance": balance.to_string(), "nonce": account.nonce}))
}

fn get_current_mini_epoch(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().number().to_string())
}

fn get_latest_tx_block(_: Params, node: &Arc<Mutex<Node>>) -> Result<zil::TxBlock> {
    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("no blocks"))?;

    Ok((&block).into())
}

fn get_minimum_gas_price(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let price = node.lock().unwrap().get_gas_price();
    // `price` is the cost per unit of [EvmGas]. This API should return the cost per unit of [ScillaGas].
    let price = price * (EVM_GAS_PER_SCILLA_GAS as u128);

    Ok(ZilAmount::from_amount(price).to_string())
}

fn get_network_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let network_id = node.lock().unwrap().chain_id.zil();
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
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();

    // First get the account and check that its a scilla account
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get latest block!"))?;

    let state = node.get_state(&block)?;
    let account = state.get_account(address)?;

    let result = json!({
        "_balance": ZilAmount::from_amount(account.balance).to_string(),
    });
    let Value::Object(mut result) = result else {
        unreachable!()
    };

    let is_scilla = account.code.scilla_code_and_init_data().is_some();
    if is_scilla {
        let limit = node.config.state_rpc_limit;

        let trie = state.get_account_trie(address)?;
        for (i, (k, v)) in trie.iter().enumerate() {
            if i >= limit {
                return Err(anyhow!(
                    "State of contract returned has size greater than the allowed maximum"
                ));
            }

            let (var_name, indices) = split_storage_key(&k)?;
            let mut var = result.entry(var_name.clone());

            for index in indices {
                let next = var.or_insert_with(|| Value::Object(Default::default()));
                let Value::Object(next) = next else {
                    unreachable!()
                };
                let key: String = serde_json::from_slice(&index)?;
                var = next.entry(key.clone());
            }

            var.or_insert(serde_json::from_slice(&v)?);
        }
    }

    Ok(result.into())
}

fn get_smart_contract_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;
    let account = node.get_state(&block)?.get_account(address)?;

    let (code, type_) = match account.code {
        Code::Evm(ref bytes) => (hex::encode(bytes), "evm"),
        Code::Scilla { code, .. } => (code, "scilla"),
    };

    Ok(json!({ "code": code, "type": type_ }))
}

fn get_smart_contract_init(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Vec<ScillaTypedVariable>> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;
    let account = node.get_state(&block)?.get_account(address)?;

    let Some((_, contract_init)) = account.code.scilla_code_and_init_data() else {
        return Err(anyhow!("Address not contract address"));
    };

    Ok(serde_json::from_str(&contract_init)?)
}

fn get_transactions_for_tx_block(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Vec<Vec<String>>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let node = node.lock().unwrap();
    let Some(block) = node.get_block(block_number)? else {
        return Err(anyhow!("Tx Block does not exist"));
    };
    if block.transactions.is_empty() {
        return Err(anyhow!("TxBlock has no transactions"));
    }

    Ok(vec![block
        .transactions
        .into_iter()
        .map(|h| B256::from(h).to_hex_no_prefix())
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
    let Some(block) = node.get_block(block_number)? else {
        return Ok(None);
    };
    let mut block: zil::TxBlock = (&block).into();

    if verbose {
        block.header.committee_hash = Some(B256::ZERO);
        block.body.cosig_bitmap_1 = vec![true; 8];
        block.body.cosig_bitmap_2 = vec![true; 8];
        let mut scalar = [0; 32];
        scalar[31] = 1;
        block.body.cosig_1 = Some(schnorr::Signature::from_scalars(scalar, scalar).unwrap());
    }

    Ok(Some(block))
}

fn get_smart_contracts(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<SmartContract>> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let block = node
        .lock()
        .unwrap()
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;

    let nonce = node
        .lock()
        .unwrap()
        .get_state(&block)?
        .get_account(address)?
        .nonce;

    let mut contracts = vec![];

    for i in 0..nonce {
        let contract_address = zil_contract_address(address, i);

        let is_scilla = node
            .lock()
            .unwrap()
            .get_state(&block)?
            .get_account(contract_address)?
            .code
            .scilla_code_and_init_data()
            .is_some();

        // Note that we only expose created Scilla contracts in this API.
        if is_scilla {
            contracts.push(SmartContract {
                address: contract_address,
            });
        }
    }

    Ok(contracts)
}

fn get_example_ds_block_verbose(dsblocknum: u64, txblocknum: u64) -> DSBlockVerbose {
    DSBlockVerbose {
        b1: vec![false, false, false],
        b2: vec![false, false],
        cs1: String::from("FBA696961142862169D03EED67DD302EAB91333CBC4EEFE7EDB230515DA31DC1B9746EEEE5E7C105685E22C483B1021867B3775D30215CA66D5D81543E9FE8B5"),
        prev_dshash: String::from("585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e"),
        header: DSBlockHeaderVerbose {
            block_num: dsblocknum.to_string(),
            committee_hash: String::from("da38b3b21b26b71835bb1545246a0a248f97003de302ae20d70aeaf854403029"),
            difficulty: 95,
            difficulty_ds: 156,
            epoch_num: txblocknum.to_string(),
            gas_price: String::from("2000000000"),
            members_ejected: vec![],
            po_wwinners: vec![],
            po_wwinners_ip: vec![],
            prev_hash: String::from("585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e"),
            reserved_field: String::from("0000000000000000000000000000000000000000000000000000000000000000"),
            swinfo: SWInfo { scilla: vec![], zilliqa: vec![] },
            sharding_hash: String::from("3216a33bfd4801e1907e72c7d529cef99c38d57cd281d0e9d726639fd9882d25"),
            timestamp: String::from("1606443830834512"),
            version: 2,
        },
        signature: String::from("7EE023C56602A17F2C8ABA2BEF290386D7C2CE1ABD8E3621573802FA67B243DE60B3EBEE5C4CCFDB697C80127B99CB384DAFEB44F70CD7569F2816DB950877BB"),
    }
}

fn get_example_ds_block(dsblocknum: u64, txblocknum: u64) -> DSBlock {
    get_example_ds_block_verbose(dsblocknum, txblocknum).into()
}

pub fn get_ds_block(params: Params, _node: &Arc<Mutex<Node>>) -> Result<DSBlock> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

pub fn get_ds_block_verbose(params: Params, _node: &Arc<Mutex<Node>>) -> Result<DSBlockVerbose> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block_verbose(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

pub fn get_latest_ds_block(_params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlock> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(get_example_ds_block(num_ds_blocks, num_tx_blocks))
}

pub fn get_current_ds_comm(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<GetCurrentDSCommResult> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(GetCurrentDSCommResult {
        current_dsepoch: num_ds_blocks.to_string(),
        current_tx_epoch: num_tx_blocks.to_string(),
        num_of_dsguard: 420,
        dscomm: vec![],
    })
}

pub fn get_current_ds_epoch(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(num_ds_blocks.to_string())
}

pub fn ds_block_listing(params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlockListingResult> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    let max_pages = num_ds_blocks / 10;
    let page_requested: String = params.one()?;
    let page_requested: u64 = page_requested.parse()?;

    let base_blocknum = page_requested * 10;
    let end_blocknum = num_ds_blocks.min(base_blocknum + 10);
    let listings: Vec<DSBlockListing> = (base_blocknum..end_blocknum)
        .map(|blocknum| DSBlockListing {
            block_num: blocknum,
            hash: "4DEED80AFDCC89D5B691DCB54CCB846AD9D823D448A56ACAC4DBE5E1213244C7".to_string(),
        })
        .collect();

    Ok(DSBlockListingResult {
        data: listings,
        max_pages: max_pages.try_into()?,
    })
}

pub fn calculate_tx_block_rate(node: &Arc<Mutex<Node>>) -> Result<f64> {
    let node = node.lock().unwrap();
    let max_measurement_blocks = 5;
    let height = node.get_chain_tip();
    if height == 0 {
        return Ok(0.0);
    }
    let measurement_blocks = height.min(max_measurement_blocks);
    let start_measure_block = node
        .consensus
        .get_block_by_number(height - measurement_blocks + 1)?
        .ok_or(anyhow!("Unable to get block"))?;
    let start_measure_time = start_measure_block.header.timestamp;
    let end_measure_time = SystemTime::now();
    let elapsed_time = end_measure_time.duration_since(start_measure_time)?;
    let tx_block_rate = measurement_blocks as f64 / elapsed_time.as_secs_f64();
    Ok(tx_block_rate)
}

pub fn get_ds_block_rate(_params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlockRateResult> {
    let tx_block_rate = calculate_tx_block_rate(node)?;
    let ds_block_rate = tx_block_rate / TX_BLOCKS_PER_DS_BLOCK as f64;
    Ok(DSBlockRateResult {
        rate: ds_block_rate,
    })
}

fn get_tx_block_rate(_params: Params, node: &Arc<Mutex<Node>>) -> Result<TXBlockRateResult> {
    let tx_block_rate = calculate_tx_block_rate(node)?;
    Ok(TXBlockRateResult {
        rate: tx_block_rate,
    })
}

fn tx_block_listing(params: Params, node: &Arc<Mutex<Node>>) -> Result<TxBlockListingResult> {
    let page_number: u64 = params.one()?;

    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_pages = (num_tx_blocks / 10) + if num_tx_blocks % 10 == 0 { 0 } else { 1 };

    let start_block = page_number * 10;
    let end_block = std::cmp::min(start_block + 10, num_tx_blocks);

    let listings: Vec<TxBlockListing> = (start_block..end_block)
        .filter_map(|block_number| {
            node.get_block(block_number)
                .ok()
                .flatten()
                .map(|block| TxBlockListing {
                    block_num: block.number(),
                    hash: block.hash().to_string(),
                })
        })
        .collect();

    Ok(TxBlockListingResult {
        data: listings,
        max_pages: num_pages,
    })
}

fn get_num_peers(_params: Params, node: &Arc<Mutex<Node>>) -> Result<u64> {
    let node = node.lock().unwrap();
    let num_peers = node.get_peer_num();
    Ok(num_peers as u64)
}

// Calculates transaction rate over the most recent block
fn get_tx_rate(_params: Params, node: &Arc<Mutex<Node>>) -> Result<f64> {
    let node = node.lock().unwrap();
    let head_block_num = node.get_chain_tip();
    if head_block_num <= 1 {
        return Ok(0.0);
    }
    let prev_block_num = head_block_num - 1;
    let head_block = node
        .get_block(head_block_num)?
        .ok_or(anyhow!("Unable to get block"))?;
    let prev_block = node
        .get_block(prev_block_num)?
        .ok_or(anyhow!("Unable to get block"))?;
    let transactions_between = head_block.transactions.len() as f64;
    let time_between = head_block
        .header
        .timestamp
        .duration_since(prev_block.header.timestamp)?;
    let transaction_rate = transactions_between / time_between.as_secs_f64();
    Ok(transaction_rate)
}

fn get_transactions_for_tx_block_ex(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<TxnsForTxBlockExResponse> {
    let mut seq = params.sequence();
    let block_number: String = seq.next()?;
    let page_number: String = seq.next()?;
    let block_number: u64 = block_number.parse()?;
    let page_number: usize = page_number.parse()?;

    let node = node.lock().unwrap();
    let block = node
        .get_block(block_number)?
        .ok_or_else(|| anyhow!("Block not found"))?;

    let total_transactions = block.transactions.len();
    let num_pages = (total_transactions / TRANSACTIONS_PER_PAGE)
        + (if total_transactions % TRANSACTIONS_PER_PAGE != 0 {
            1
        } else {
            0
        });

    // Ensure page is within bounds
    if page_number >= num_pages {
        return Ok(TxnsForTxBlockExResponse {
            curr_page: page_number as u64,
            num_pages: num_pages as u64,
            transactions: vec![],
        });
    }

    let start = std::cmp::min(page_number * TRANSACTIONS_PER_PAGE, total_transactions);

    let end = std::cmp::min(start + TRANSACTIONS_PER_PAGE, total_transactions);
    let slice = block.transactions[start..end].to_vec();

    Ok(TxnsForTxBlockExResponse {
        curr_page: page_number as u64,
        num_pages: num_pages as u64,
        transactions: slice
            .into_iter()
            .map(|h| B256::from(h).to_hex_no_prefix())
            .collect(),
    })
}

fn get_txn_bodies_for_tx_block_ex(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<TxnBodiesForTxBlockExResponse> {
    let params: Vec<String> = params.parse()?;
    let block_number: u64 = params[0].parse()?;
    let page_number: usize = params[1].parse()?;

    let node = node.lock().expect("Failed to acquire lock on node");
    let block = node
        .get_block(block_number)?
        .ok_or_else(|| anyhow!("Block not found"))?;

    let total_transactions = block.transactions.len();
    let num_pages = (total_transactions / TRANSACTIONS_PER_PAGE)
        + (if total_transactions % TRANSACTIONS_PER_PAGE != 0 {
            1
        } else {
            0
        });

    // Ensure page is within bounds
    if page_number >= num_pages {
        return Ok(TxnBodiesForTxBlockExResponse {
            curr_page: page_number as u64,
            num_pages: num_pages as u64,
            transactions: vec![],
        });
    }

    let start = std::cmp::min(page_number * TRANSACTIONS_PER_PAGE, total_transactions);

    let end = std::cmp::min(start + TRANSACTIONS_PER_PAGE, total_transactions);

    let mut transactions = Vec::with_capacity(end - start);
    for hash in &block.transactions[start..end] {
        let tx = node
            .get_transaction_by_hash(*hash)?
            .ok_or(anyhow!("Transaction hash missing"))?;
        let nonce = tx.tx.nonce().unwrap_or_default();
        let amount = tx.tx.zil_amount();
        let gas_price = tx.tx.gas_price_per_scilla_gas();
        let gas_limit = tx.tx.gas_limit_scilla();
        let receipt = node
            .get_transaction_receipt(*hash)?
            .ok_or(anyhow!("Transaction receipt missing"))?;
        let (version, to_addr, sender_pub_key, signature, _code, _data) = match tx.tx {
            SignedTransaction::Zilliqa { tx, sig, key } => (
                ((tx.chain_id as u32) << 16) | 1,
                tx.to_addr,
                key.to_encoded_point(true).as_bytes().to_hex(),
                <[u8; 64]>::from(sig.to_bytes()).to_hex(),
                (!tx.code.is_empty()).then_some(tx.code),
                (!tx.data.is_empty()).then_some(tx.data),
            ),
            SignedTransaction::Legacy { tx, sig } => (
                ((tx.chain_id.unwrap_or_default() as u32) << 16) | 2,
                tx.to.to().copied().unwrap_or_default(),
                sig.recover_from_prehash(&tx.signature_hash())?
                    .to_sec1_bytes()
                    .to_hex(),
                sig.as_bytes().to_hex(),
                tx.to.is_create().then(|| hex::encode(&tx.input)),
                tx.to.is_call().then(|| hex::encode(&tx.input)),
            ),
            SignedTransaction::Eip2930 { tx, sig } => (
                ((tx.chain_id as u32) << 16) | 3,
                tx.to.to().copied().unwrap_or_default(),
                sig.recover_from_prehash(&tx.signature_hash())?
                    .to_sec1_bytes()
                    .to_hex(),
                sig.as_bytes().to_hex(),
                tx.to.is_create().then(|| hex::encode(&tx.input)),
                tx.to.is_call().then(|| hex::encode(&tx.input)),
            ),
            SignedTransaction::Eip1559 { tx, sig } => (
                ((tx.chain_id as u32) << 16) | 4,
                tx.to.to().copied().unwrap_or_default(),
                sig.recover_from_prehash(&tx.signature_hash())?
                    .to_sec1_bytes()
                    .to_hex(),
                sig.as_bytes().to_hex(),
                tx.to.is_create().then(|| hex::encode(&tx.input)),
                tx.to.is_call().then(|| hex::encode(&tx.input)),
            ),
            SignedTransaction::Intershard { tx, .. } => (
                ((tx.chain_id as u32) << 16) | 20,
                tx.to_addr.unwrap_or_default(),
                String::new(),
                String::new(),
                tx.to_addr.is_none().then(|| hex::encode(&tx.payload)),
                tx.to_addr.is_some().then(|| hex::encode(&tx.payload)),
            ),
        };
        let body = TransactionBody {
            id: tx.hash.to_string(),
            amount: amount.to_string(),
            gas_limit: gas_limit.to_string(),
            gas_price: gas_price.to_string(),
            nonce: nonce.to_string(),
            receipt,
            sender_pub_key,
            signature,
            to_addr: to_addr.to_string(),
            version: version.to_string(),
        };
        transactions.push(body);
    }

    Ok(TxnBodiesForTxBlockExResponse {
        curr_page: page_number as u64,
        num_pages: num_pages as u64,
        transactions,
    })
}
