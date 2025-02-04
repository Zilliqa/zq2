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
use jsonrpsee::{
    types::{ErrorObject, Params},
    RpcModule,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::digest::generic_array::{
    sequence::Split,
    typenum::{U12, U20},
    GenericArray,
};

use super::{
    to_hex::ToHex,
    types::zil::{
        self, BlockchainInfo, DSBlock, DSBlockHeaderVerbose, DSBlockListing, DSBlockListingResult,
        DSBlockRateResult, DSBlockVerbose, GetCurrentDSCommResult, MinerInfo,
        RecentTransactionsResponse, SWInfo, ShardingStructure, SmartContract, StateProofResponse,
        TXBlockRateResult, TransactionBody, TransactionReceiptResponse, TransactionStatusResponse,
        TxBlockListing, TxBlockListingResult, TxnBodiesForTxBlockExResponse,
        TxnsForTxBlockExResponse,
    },
};
use crate::{
    api::types::zil::{CreateTransactionResponse, GetTxResponse, RPCErrorCode},
    cfg::EnabledApi,
    crypto::Hash,
    exec::zil_contract_address,
    message::Block,
    node::Node,
    pool::TxAddResult,
    schnorr,
    scilla::{split_storage_key, storage_key, ParamValue},
    state::Code,
    time::SystemTime,
    transaction::{
        ScillaGas, SignedTransaction, TxZilliqa, ValidationOutcome, ZilAmount,
        EVM_GAS_PER_SCILLA_GAS,
    },
};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
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
            ("GetTxBlock", get_tx_block),
            ("GetTxBlockVerbose", get_tx_block_verbose),
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
            ("GetTxnBodiesForTxBlock", get_txn_bodies_for_tx_block),
            ("GetTxnBodiesForTxBlockEx", get_txn_bodies_for_tx_block_ex),
            ("GetNumDSBlocks", get_num_ds_blocks),
            ("GetRecentTransactions", get_recent_transactions),
            ("GetNumTransactions", get_num_transactions),
            ("GetNumTxnsTXEpoch", get_num_txns_tx_epoch),
            ("GetNumTxnsDSEpoch", get_num_txns_ds_epoch),
            ("GetTotalCoinSupply", get_total_coin_supply),
            ("GetTotalCoinSupplyAsInt", get_total_coin_supply_as_int),
            ("GetMinerInfo", get_miner_info),
            ("GetNodeType", get_node_type),
            ("GetPrevDifficulty", get_prev_difficulty),
            ("GetPrevDSDifficulty", get_prev_ds_difficulty),
            ("GetShardingStructure", get_sharding_structure),
            ("GetSmartContractSubState", get_smart_contract_sub_state),
            (
                "GetSoftConfirmedTransaction",
                get_soft_confirmed_transaction
            ),
            ("GetStateProof", get_state_proof),
            ("GetTransactionStatus", get_transaction_status),
        ],
    )
}

/// Take an Address and produce a checksummed hex representation of it.
/// No initial 0x will be added.
/// Public because some of the tests require it.
pub fn to_zil_checksum_string(address: &Address) -> String {
    const UPPER_CHARS: [char; 6] = ['A', 'B', 'C', 'D', 'E', 'F'];
    const LOWER_CHARS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let bytes = address.into_array();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut result = String::new();
    // You could do this with iterators, but it's horrid.
    for (idx, byte) in bytes.iter().enumerate() {
        for nibble in 0..2 {
            let shift = (1 - nibble) << 2;
            let val = (byte >> shift) & 0xf;
            // Should this be uppercase?
            let bit_num = 6 * ((idx << 1) + nibble);
            let bit = digest[bit_num >> 3] & (1 << (7 - (bit_num & 7)));
            if bit != 0 && val > 9 {
                result.push(UPPER_CHARS[usize::from(val - 10)])
            } else {
                result.push(LOWER_CHARS[usize::from(val)])
            }
        }
    }
    result
}

#[derive(Deserialize)]
#[serde(transparent)]
pub struct ZilAddress {
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
    to_addr: String,
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
/// Helper function to extract signer address from a public key
fn extract_signer_address(key: &schnorr::PublicKey) -> Address {
    let hashed = Sha256::digest(key.to_encoded_point(true).as_bytes());
    let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();
    Address::new(bytes.into())
}

// CreateTransaction
fn create_transaction(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<CreateTransactionResponse> {
    let transaction: TransactionParams = params.one()?;

    let mut node = node.lock().unwrap();

    let version = transaction.version & 0xffff;
    let chain_id = transaction.version >> 16;

    if (chain_id as u64) != (node.chain_id.zil()) {
        Err(ErrorObject::owned::<String>(
            RPCErrorCode::RpcVerifyRejected as i32,
            format!(
                "unexpected chain ID, expected: {}, got: {chain_id}",
                node.chain_id.zil()
            ),
            None,
        ))?;
    }

    if version != 1 {
        Err(ErrorObject::owned::<String>(
            RPCErrorCode::RpcVerifyRejected as i32,
            format!("unexpected version, expected: 1, got: {version}"),
            None,
        ))?;
    }

    let pre_key = hex::decode(transaction.pub_key).map_err(|_|
                // This is apparently what ZQ1 does.
                ErrorObject::owned::<String>(RPCErrorCode::RpcVerifyRejected as i32,
                                   "Cannot parse public key".to_string(),
                                   None))?;

    let key = schnorr::PublicKey::from_sec1_bytes(&pre_key).map_err(|_|
                 // This is apparently what ZQ1 does.
                 ErrorObject::owned::<String>(RPCErrorCode::RpcVerifyRejected as i32,
                                              "Invalid public key".to_string(),
                                              None))?;

    // Addresses without an 0x prefix are legal.
    let corrected_addr = if transaction.to_addr.starts_with("0x") {
        transaction.to_addr
    } else {
        format!("0x{0}", transaction.to_addr)
    };
    let to_addr = Address::parse_checksummed(&corrected_addr, None).or_else(|_| {
        // Not eth checksummed. How about Zilliqa?
        let addr = Address::from_str(&corrected_addr)?;
        let summed = format!("0x{0}", to_zil_checksum_string(&addr));
        if summed == corrected_addr {
            Ok(addr)
        } else {
            // Copied from ZQ1
            Err(anyhow!("To Addr checksum wrong"))
        }
    })?;

    let sig = schnorr::Signature::from_str(&transaction.signature).map_err(|err| {
        ErrorObject::owned::<String>(
            RPCErrorCode::RpcVerifyRejected as i32,
            format!("Cannot extract signature - {}", err),
            None,
        )
    })?;

    // If we don't trap this here, it will later cause the -1 in
    // transaction::get_nonce() to pan1ic.
    if transaction.nonce == 0 {
        Err(ErrorObject::owned::<String>(
            RPCErrorCode::RpcInvalidParameter as i32,
            "Invalid nonce (0)".to_string(),
            None,
        ))?;
    }

    let tx = TxZilliqa {
        chain_id: chain_id as u16,
        nonce: transaction.nonce,
        gas_price: transaction.gas_price,
        gas_limit: transaction.gas_limit,
        to_addr,
        amount: transaction.amount,
        code: transaction.code.unwrap_or_default(),
        data: transaction.data.unwrap_or_default(),
    };
    let signed_transaction = SignedTransaction::Zilliqa {
        tx: tx.clone(),
        key,
        sig,
    };

    let (transaction_hash, result) = node.create_transaction(signed_transaction.clone())?;
    let info = match result {
        TxAddResult::AddedToMempool => Ok("Txn processed".to_string()),
        TxAddResult::Duplicate(_) => Ok("Txn already present".to_string()),
        TxAddResult::SameNonceButLowerGasPrice => {
            // Ideally it would be nice to return an error here, but we would break compatibility if we did.
            Ok("Another transaction exists with the same nonce but a higher gas price".to_string())
        }
        TxAddResult::CannotVerifySignature => Err(ErrorObject::owned::<String>(
            RPCErrorCode::RpcVerifyRejected as i32,
            "Cannot verify signature".to_string(),
            None,
        )),
        TxAddResult::ValidationFailed(reason) => {
            let code = match &reason {
                ValidationOutcome::InsufficientGasZil(_, _)
                | ValidationOutcome::InsufficientGasEvm(_, _)
                | ValidationOutcome::NonceTooLow(_, _)
                | ValidationOutcome::InsufficientFunds(_, _)
                | ValidationOutcome::BlockGasLimitExceeded(_, _) => {
                    RPCErrorCode::RpcInvalidParameter
                }
                _ => RPCErrorCode::RpcVerifyRejected,
            };
            Err(ErrorObject::owned::<String>(
                code as i32,
                reason.to_msg_string(),
                None,
            ))
        }
        TxAddResult::NonceTooLow(got, expected) => {
            Ok(format!("Nonce ({got}) lower than current ({expected})"))
        }
    }?;
    let contract_address = if !tx.code.is_empty() {
        let signer = extract_signer_address(&key);
        Some(zil_contract_address(signer, tx.nonce - 1))
    } else {
        None
    };

    let response = CreateTransactionResponse {
        contract_address,
        info,
        tran_id: transaction_hash.0.into(),
    };

    Ok(response)
}

// GetContractAddressFromTransactionID
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

// GetTransaction
fn get_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<GetTxResponse> {
    let jsonrpc_error_data: Option<String> = None;
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let node = node.lock().unwrap();

    let tx = node.get_transaction_by_hash(hash)?.ok_or_else(|| {
        ErrorObject::owned(
            RPCErrorCode::RpcDatabaseError as i32,
            "Txn Hash not Present".to_string(),
            jsonrpc_error_data.clone(),
        )
    })?;
    let receipt = node.get_transaction_receipt(hash)?.ok_or_else(|| {
        jsonrpsee::types::ErrorObject::owned(
            RPCErrorCode::RpcDatabaseError as i32,
            "Txn Hash not Present".to_string(),
            jsonrpc_error_data.clone(),
        )
    })?;
    let block = node
        .get_block(receipt.block_hash)?
        .ok_or_else(|| anyhow!("block does not exist"))?;
    if block.number() > node.get_finalized_height()? {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcDatabaseError as i32,
            "Block not finalized".to_string(),
            jsonrpc_error_data,
        )
        .into());
    }

    GetTxResponse::new(tx, receipt, block.number())
}

// GetBalance
fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get latest block!"))?;

    let state = node.get_state(&block)?;

    if !state.has_account(address)? {
        return Err(ErrorObject::owned(
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

// GetCurrentMiniEpoch
fn get_current_mini_epoch(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().number().to_string())
}

// GetLatestTxBlock
fn get_latest_tx_block(_: Params, node: &Arc<Mutex<Node>>) -> Result<zil::TxBlock> {
    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("no blocks"))?;

    let txn_fees = get_txn_fees_for_block(&node, block.hash())?;
    let tx_block: zil::TxBlock = zil::TxBlock::new(&block, txn_fees);
    Ok(tx_block)
}

// GetMinimumGasPrice
fn get_minimum_gas_price(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let price = node.lock().unwrap().get_gas_price();
    // `price` is the cost per unit of [EvmGas]. This API should return the cost per unit of [ScillaGas].
    let price = price * (EVM_GAS_PER_SCILLA_GAS as u128);

    Ok(ZilAmount::from_amount(price).to_string())
}

// GetNetworkId
fn get_network_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let network_id = node.lock().unwrap().chain_id.zil();
    Ok(network_id.to_string())
}

// GetVersion
fn get_version(_: Params, _: &Arc<Mutex<Node>>) -> Result<Value> {
    let commit = env!("VERGEN_GIT_SHA");
    let version = env!("VERGEN_GIT_DESCRIBE");
    Ok(json!({
        "Commit": commit,
        "Version": version,
    }))
}

// GetBlockchainInfo
fn get_blockchain_info(_: Params, node: &Arc<Mutex<Node>>) -> Result<BlockchainInfo> {
    let transaction_rate = get_tx_rate(Params::new(None), node)?;
    let tx_block_rate = calculate_tx_block_rate(node)?;
    let sharding_structure = get_sharding_structure(Params::new(None), node)?;

    let node = node.lock().unwrap();

    let num_peers = node.get_peer_num();
    let num_tx_blocks = node.get_latest_finalized_block_number()?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    let num_transactions = node.consensus.block_store.get_num_transactions()?;
    let ds_block_rate = tx_block_rate / TX_BLOCKS_PER_DS_BLOCK as f64;

    // num_txns_ds_epoch
    let current_epoch = node.get_latest_finalized_block_number()? / TX_BLOCKS_PER_DS_BLOCK;
    let current_epoch_first = current_epoch * TX_BLOCKS_PER_DS_BLOCK;
    let mut num_txns_ds_epoch = 0;
    for i in current_epoch_first..node.get_latest_finalized_block_number()? {
        let block = node
            .get_block(i)?
            .ok_or_else(|| anyhow!("Block not found"))?;
        num_txns_ds_epoch += block.transactions.len();
    }

    // num_txns_tx_epoch
    let latest_block = node.get_latest_finalized_block()?;
    let num_txns_tx_epoch = match latest_block {
        Some(block) => block.transactions.len(),
        None => 0,
    };

    Ok(BlockchainInfo {
        num_peers: num_peers as u16,
        num_tx_blocks,
        num_ds_blocks,
        num_transactions: num_transactions as u64,
        transaction_rate,
        tx_block_rate,
        ds_block_rate,
        current_mini_epoch: num_tx_blocks,
        current_ds_epoch: num_ds_blocks,
        num_txns_ds_epoch: num_txns_ds_epoch as u64,
        num_txns_tx_epoch: num_txns_tx_epoch as u64,
        sharding_structure,
    })
}

// GetNumTxBlocks
fn get_num_tx_blocks(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();

    Ok(node.get_latest_finalized_block_number()?.to_string())
}

// GetSmartContractState
fn get_smart_contract_state(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let mut seq = params.sequence();
    let address: ZilAddress = seq.next()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();

    // First get the account and check that its a scilla account
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get latest block!"))?;

    let state = node.get_state(&block)?;
    if !state.has_account(address)? {
        return Err(anyhow!(
            "Address does not exist: {}",
            hex::encode(address.0)
        ));
    }
    let account = state.get_account(address)?;

    let result = json!({
        "_balance": ZilAmount::from_amount(account.balance).to_string(),
    });
    let Value::Object(mut result) = result else {
        unreachable!()
    };

    if account.code.is_scilla() {
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

            for index in indices.iter() {
                let next = var.or_insert_with(|| Value::Object(Default::default()));
                let Value::Object(next) = next else {
                    unreachable!()
                };
                let key: String = serde_json::from_slice(index)?;
                var = next.entry(key.clone());
            }

            let field_defs = match &account.code {
                Code::Scilla { types, .. } => types,
                _ => unreachable!(),
            };
            let (_, depth) = field_defs.get(&var_name).unwrap();
            let depth = *depth as usize;

            let convert_result = serde_json::from_slice(&v);
            if depth > 0 && indices.len() < depth {
                if convert_result.is_err() {
                    var.or_insert(Value::Object(Default::default()));
                }
            } else {
                var.or_insert(convert_result?);
            }
        }
    }

    Ok(result.into())
}

// GetSmartContractCode
fn get_smart_contract_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;
    let state = node.get_state(&block)?;

    if !state.has_account(address)? {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            format!("Address does not exist: {}", address),
            None::<()>,
        )
        .into());
    }
    let account = state.get_account(address)?;

    let (code, type_) = match account.code {
        Code::Evm(ref bytes) => (hex::encode(bytes), "evm"),
        Code::Scilla { code, .. } => (code, "scilla"),
    };

    Ok(json!({ "code": code, "type": type_ }))
}

// GetSmartContractInit
fn get_smart_contract_init(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<ParamValue>> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;

    let state = node.get_state(&block)?;

    if !state.has_account(address)? {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            "Address does not exist".to_string(),
            None::<()>,
        )
        .into());
    }
    let account = state.get_account(address)?;

    let Some((_, init_data)) = account.code.scilla_code_and_init_data() else {
        return Err(anyhow!("Address does not exist"));
    };

    Ok(init_data.to_vec())
}

// GetTransactionsForTxBlock
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

// GetTxBlock
fn get_tx_block(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<zil::TxBlock>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let node = node.lock().unwrap();
    let Some(block) = node.get_block(block_number)? else {
        return Ok(None);
    };
    if block.number() > node.get_finalized_height()? {
        return Err(anyhow!("Block not finalized"));
    }
    let txn_fees = get_txn_fees_for_block(&node, block.hash())?;
    let block: zil::TxBlock = zil::TxBlock::new(&block, txn_fees);

    Ok(Some(block))
}

fn get_txn_fees_for_block(node: &Node, hash: Hash) -> Result<u128> {
    Ok(node
        .get_transaction_receipts_in_block(hash)?
        .iter()
        .fold(0, |acc, txnrcpt| {
            let txn = node
                .get_transaction_by_hash(txnrcpt.tx_hash)
                .unwrap()
                .unwrap();
            acc + ((txnrcpt.gas_used.0 as u128) * txn.tx.gas_price_per_evm_gas())
        }))
}

// GetTxBlockVerbose
fn get_tx_block_verbose(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<zil::TxBlockVerbose>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let node = node.lock().unwrap();
    let Some(block) = node.get_block(block_number)? else {
        return Ok(None);
    };
    if block.number() > node.get_finalized_height()? {
        return Err(anyhow!("Block not finalized"));
    }
    let proposer = node
        .get_proposer_reward_address(block.header)?
        .expect("No proposer");
    let txn_fees = get_txn_fees_for_block(&node, block.hash())?;
    let block: zil::TxBlockVerbose = zil::TxBlockVerbose::new(&block, txn_fees, proposer);

    Ok(Some(block))
}

// GetSmartContracts
fn get_smart_contracts(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<SmartContract>> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let block = node
        .lock()
        .unwrap()
        .get_latest_finalized_block()?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;

    let state = node.lock().unwrap().get_state(&block)?;

    if !state.has_account(address)? {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            "Address does not exist".to_string(),
            None::<()>,
        )
        .into());
    }

    let account = state.get_account(address)?;

    if !account.code.is_eoa() {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            "A contract account queried".to_string(),
            None::<()>,
        )
        .into());
    }

    let nonce = account.nonce;

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

// GetDSBlock
pub fn get_ds_block(params: Params, _node: &Arc<Mutex<Node>>) -> Result<DSBlock> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

// GetDSBlockVerbose
pub fn get_ds_block_verbose(params: Params, _node: &Arc<Mutex<Node>>) -> Result<DSBlockVerbose> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block_verbose(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

// GetLatestDSBlock
pub fn get_latest_ds_block(_params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlock> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_latest_finalized_block_number()?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(get_example_ds_block(num_ds_blocks, num_tx_blocks))
}

// GetCurrentDSComm
pub fn get_current_ds_comm(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<GetCurrentDSCommResult> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_latest_finalized_block_number()?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(GetCurrentDSCommResult {
        current_dsepoch: num_ds_blocks.to_string(),
        current_tx_epoch: num_tx_blocks.to_string(),
        num_of_dsguard: 420,
        dscomm: vec![],
    })
}

// GetCurrentDSEpoch
pub fn get_current_ds_epoch(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_latest_finalized_block_number()?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(num_ds_blocks.to_string())
}

// DSBlockListing
pub fn ds_block_listing(params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlockListingResult> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_latest_finalized_block_number()?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    let max_pages = num_ds_blocks / 10;
    let page_requested: u64 = params.one()?;

    let base_blocknum = page_requested * 10;
    let end_blocknum = num_ds_blocks.min(base_blocknum + 10);
    let listings: Vec<DSBlockListing> = (base_blocknum..end_blocknum)
        .rev()
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

// utilitiy function to calculate the tx block rate for get_ds_block_rate and get_tx_block_rate
pub fn calculate_tx_block_rate(node: &Arc<Mutex<Node>>) -> Result<f64> {
    let node = node.lock().unwrap();
    let max_measurement_blocks = 5;
    let height = node.get_latest_finalized_block_number()?;
    if height == 0 {
        return Ok(0.0);
    }
    let measurement_blocks = height.min(max_measurement_blocks);
    let start_measure_block = node
        .get_block(height - measurement_blocks + 1)?
        .ok_or(anyhow!("Unable to get block"))?;
    let start_measure_time = start_measure_block.header.timestamp;
    let end_measure_time = SystemTime::now();
    let elapsed_time = end_measure_time.duration_since(start_measure_time)?;
    let tx_block_rate = measurement_blocks as f64 / elapsed_time.as_secs_f64();
    Ok(tx_block_rate)
}

// GetDSBlockRate
pub fn get_ds_block_rate(_params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlockRateResult> {
    let tx_block_rate = calculate_tx_block_rate(node)?;
    let ds_block_rate = tx_block_rate / TX_BLOCKS_PER_DS_BLOCK as f64;
    Ok(DSBlockRateResult {
        rate: ds_block_rate,
    })
}

// GetTxBlockRate
fn get_tx_block_rate(_params: Params, node: &Arc<Mutex<Node>>) -> Result<TXBlockRateResult> {
    let tx_block_rate = calculate_tx_block_rate(node)?;
    Ok(TXBlockRateResult {
        rate: tx_block_rate,
    })
}

// TxBlockListing
fn tx_block_listing(params: Params, node: &Arc<Mutex<Node>>) -> Result<TxBlockListingResult> {
    let page_number: u64 = params.one()?;

    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_latest_finalized_block_number()?;
    let num_pages = (num_tx_blocks / 10) + if num_tx_blocks % 10 == 0 { 0 } else { 1 };

    let start_block = page_number * 10;
    let end_block = std::cmp::min(start_block + 10, num_tx_blocks);

    let listings: Vec<TxBlockListing> = (start_block..end_block)
        .rev()
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

// GetNumPeers
fn get_num_peers(_params: Params, node: &Arc<Mutex<Node>>) -> Result<u64> {
    let node = node.lock().unwrap();
    let num_peers = node.get_peer_num();
    Ok(num_peers as u64)
}

// GetTransactionRate
// Calculates transaction rate over the most recent block
fn get_tx_rate(_params: Params, node: &Arc<Mutex<Node>>) -> Result<f64> {
    let node = node.lock().unwrap();
    let head_block_num = node.get_latest_finalized_block_number()?;
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
    let transactions_both = prev_block.transactions.len() + head_block.transactions.len();
    let time_between = head_block
        .header
        .timestamp
        .duration_since(prev_block.header.timestamp)?;
    let transaction_rate = transactions_both as f64 / time_between.as_secs_f64();
    Ok(transaction_rate)
}

// GetTransactionsForTxBlockEx
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
    if block.number() > node.get_finalized_height()? {
        return Err(anyhow!("Block not finalized"));
    }

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

// GetTransactionsForTxBlockEx
fn extract_transaction_bodies(block: &Block, node: &Node) -> Result<Vec<TransactionBody>> {
    let mut transactions = Vec::with_capacity(block.transactions.len());
    for hash in &block.transactions {
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
        let receipt_response = TransactionReceiptResponse {
            cumulative_gas: ScillaGas::from(receipt.cumulative_gas_used).to_string(),
            epoch_num: block.number().to_string(),
            success: receipt.success,
        };
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
            receipt: receipt_response,
            sender_pub_key,
            signature,
            to_addr: to_addr.to_string(),
            version: version.to_string(),
        };
        transactions.push(body);
    }
    Ok(transactions)
}

// GetTxnBodiesForTxBlock
fn get_txn_bodies_for_tx_block(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Vec<TransactionBody>> {
    let params: Vec<String> = params.parse()?;
    let block_number: u64 = params[0].parse()?;

    let node = node.lock().expect("Failed to acquire lock on node");
    let block = node
        .get_block(block_number)?
        .ok_or_else(|| anyhow!("Block not found"))?;

    if block.number() > node.get_finalized_height()? {
        return Err(anyhow!("Block not finalized"));
    }

    extract_transaction_bodies(&block, &node)
}

// GetTxnBodiesForTxBlockEx
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

    if block.number() > node.get_finalized_height()? {
        return Err(anyhow!("Block not finalized"));
    }

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

    let transactions = extract_transaction_bodies(&block, &node)?
        .into_iter()
        .skip(start)
        .take(end - start)
        .collect();

    Ok(TxnBodiesForTxBlockExResponse {
        curr_page: page_number as u64,
        num_pages: num_pages as u64,
        transactions,
    })
}

// GetNumDSBlocks
fn get_num_ds_blocks(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_latest_finalized_block_number()?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(num_ds_blocks.to_string())
}

// GetRecentTransactions
fn get_recent_transactions(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<RecentTransactionsResponse> {
    let node = node.lock().unwrap();
    let mut block_number = node.get_latest_finalized_block_number()?;
    let mut txns = Vec::new();
    let mut blocks_searched = 0;
    while block_number > 0 && txns.len() < 100 && blocks_searched < 100 {
        let block = match node.get_block(block_number)? {
            Some(block) => block,
            None => continue,
        };
        for txn in block.transactions {
            txns.push(txn.to_string());
            if txns.len() >= 100 {
                break;
            }
        }
        block_number -= 1;
        blocks_searched += 1;
    }

    Ok(RecentTransactionsResponse {
        number: txns.len() as u64,
        txn_hashes: txns,
    })
}

// GetNumTransactions
fn get_num_transactions(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();
    let num_transactions = node.consensus.block_store.get_num_transactions()?;
    Ok(num_transactions.to_string())
}

// GetNumTxnsTXEpoch
fn get_num_txns_tx_epoch(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();
    let latest_block = node.get_latest_finalized_block()?;
    let num_transactions = match latest_block {
        Some(block) => block.transactions.len(),
        None => 0,
    };
    Ok(num_transactions.to_string())
}

// GetNumTxnsDSEpoch
fn get_num_txns_ds_epoch(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();
    let ds_epoch_size = TX_BLOCKS_PER_DS_BLOCK;
    let current_epoch = node.get_latest_finalized_block_number()? / ds_epoch_size;
    let current_epoch_first = current_epoch * ds_epoch_size;
    let mut num_txns_epoch = 0;
    for i in current_epoch_first..node.get_latest_finalized_block_number()? {
        let block = node
            .get_block(i)?
            .ok_or_else(|| anyhow!("Block not found"))?;
        num_txns_epoch += block.transactions.len();
    }
    Ok(num_txns_epoch.to_string())
}

// GetTotalCoinSupply
fn get_total_coin_supply(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();
    Ok(node.config.consensus.total_native_token_supply.to_string())
}

// GetTotalCoinSupplyAsInt
fn get_total_coin_supply_as_int(_params: Params, node: &Arc<Mutex<Node>>) -> Result<u128> {
    let node = node.lock().unwrap();
    Ok(node.config.consensus.total_native_token_supply.0)
}

// GetMinerInfo
fn get_miner_info(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<MinerInfo> {
    // This endpoint was previously queries by DS block number, which no longer exists, and
    // neither do DS committees, so it now returns placeholder data for all queries to stay ZQ1 compatible.

    Ok(MinerInfo {
        dscommittee: vec![],
        shards: vec![],
    })
}

// GetNodeType
fn get_node_type(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok("Seed".into())
}

// GetPrevDifficulty
fn get_prev_difficulty(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<u64> {
    Ok(0)
}

// GetPrevDSDifficulty
fn get_prev_ds_difficulty(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<u64> {
    Ok(0)
}

// GetShardingStructure
fn get_sharding_structure(_params: Params, node: &Arc<Mutex<Node>>) -> Result<ShardingStructure> {
    let node = node.lock().unwrap();
    let num_peers = node.get_peer_num();

    Ok(ShardingStructure {
        num_peers: vec![num_peers as u64],
    })
}

// GetSmartContractSubState
fn get_smart_contract_sub_state(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let mut seq = params.sequence();
    let address: ZilAddress = seq.next()?;
    let address: Address = address.into();
    let var_name: String = match seq.optional_next()? {
        Some(x) => x,
        None => return get_smart_contract_state(params, node),
    };
    let requested_indices: Vec<String> = seq.optional_next()?.unwrap_or_default();
    let node = node.lock().unwrap();
    if requested_indices.len() > node.config.state_rpc_limit {
        return Err(anyhow!(
            "Requested indices exceed the limit of {}",
            node.config.state_rpc_limit
        ));
    }

    // First get the account and check that its a scilla account
    let block = node
        .get_latest_finalized_block()?
        .ok_or_else(|| anyhow!("Unable to get latest block!"))?;

    let state = node.get_state(&block)?;

    if !state.has_account(address)? {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            "Address does not exist".to_string(),
            None::<()>,
        )
        .into());
    }

    let account = state.get_account(address)?;

    let result = json!({
        "_balance": ZilAmount::from_amount(account.balance).to_string(),
    });
    let Value::Object(mut result) = result else {
        unreachable!()
    };

    if account.code.clone().scilla_code_and_init_data().is_some() {
        let trie = state.get_account_trie(address)?;

        let indicies_encoded = requested_indices
            .iter()
            .map(|x| serde_json::to_vec(&x))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let prefix = storage_key(&var_name, &indicies_encoded);
        let mut n = 0;
        for (k, v) in trie.iter_by_prefix(&prefix)? {
            n += 1;
            if n > node.config.state_rpc_limit {
                return Err(anyhow!(
                    "Requested indices exceed the limit of {}",
                    node.config.state_rpc_limit
                ));
            }

            let (var_name, indices) = split_storage_key(&k)?;
            let mut var = result.entry(var_name.clone());

            for index in indices.iter() {
                let next = var.or_insert_with(|| Value::Object(Default::default()));
                let Value::Object(next) = next else {
                    unreachable!()
                };
                let key: String = serde_json::from_slice(index)?;
                var = next.entry(key.clone());
            }

            let code = &account.code;

            let field_defs = match code {
                Code::Scilla { types, .. } => types.clone(),
                _ => unreachable!(),
            };
            let (_, depth) = field_defs.get(&var_name).unwrap();
            let depth = *depth as usize;

            let convert_result = serde_json::from_slice(&v);
            if depth > 0 && indices.len() < depth {
                if convert_result.is_err() {
                    var.or_insert(Value::Object(Default::default()));
                }
            } else {
                var.or_insert(convert_result?);
            }
        }
    }
    Ok(result.into())
}

// GetSoftConfirmedTransaction
fn get_soft_confirmed_transaction(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<GetTxResponse> {
    get_transaction(params, node)
}

// GetStateProof
fn get_state_proof(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<StateProofResponse> {
    // State proof isn't meaningful in ZQ2
    Ok(StateProofResponse {
        account_proof: vec![],
        state_proof: vec![],
    })
}

// GetTransactionStatus
fn get_transaction_status(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<TransactionStatusResponse> {
    let jsonrpc_error_data: Option<String> = None;
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let node = node.lock().unwrap();
    let transaction =
        node.get_transaction_by_hash(hash)?
            .ok_or(jsonrpsee::types::ErrorObject::owned(
                RPCErrorCode::RpcDatabaseError as i32,
                "Txn Hash not found".to_string(),
                jsonrpc_error_data.clone(),
            ))?;
    let receipt =
        node.get_transaction_receipt(hash)?
            .ok_or(jsonrpsee::types::ErrorObject::owned(
                RPCErrorCode::RpcDatabaseError as i32,
                "Txn receipt not found".to_string(),
                jsonrpc_error_data.clone(),
            ))?;
    let block = node
        .get_block(receipt.block_hash)?
        .ok_or(jsonrpsee::types::ErrorObject::owned(
            RPCErrorCode::RpcDatabaseError as i32,
            "Block not found".to_string(),
            jsonrpc_error_data.clone(),
        ))?;

    let res = TransactionStatusResponse::new(transaction, receipt, block)?;
    Ok(res)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_hex_checksum() {
        use alloy::primitives::{address, Address};

        use crate::api::zilliqa::to_zil_checksum_string;

        let cases: Vec<(Address, &str)> = vec![
            (
                address!("0000000000000000000000000000000000000002"),
                "0000000000000000000000000000000000000002",
            ),
            (
                address!("1234567890123456789012345678901234567890"),
                "1234567890123456789012345678901234567890",
            ),
            (
                address!("12a45b789d1f345c789def456789012be3467890"),
                "12a45b789D1F345c789dEf456789012bE3467890",
            ),
            (
                address!("f61477d7919478e5affe1fbd9a0cdceee9fde42d"),
                "f61477D7919478e5AfFe1fbd9A0CDCeee9fdE42d",
            ),
            (
                address!("4d76f701e16d7d481de292499718db36450d6a18"),
                "4d76f701E16D7d481dE292499718db36450d6A18",
            ),
            (
                address!("6e1757590ce532ff0f0e100139e36b7ee8049ce1"),
                "6e1757590ce532Ff0F0e100139e36b7eE8049ce1",
            ),
        ];
        for (address, good) in cases.iter() {
            let summed = to_zil_checksum_string(address);
            assert_eq!(&summed, good)
        }
    }
}
