//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::{fmt::Display, str::FromStr, sync::Arc};

use alloy::{
    consensus::SignableTransaction,
    eips::{BlockId, BlockNumberOrTag},
    hex,
    primitives::{Address, B256},
};
use anyhow::{Result, anyhow};
use jsonrpsee::{
    RpcModule,
    types::{ErrorObject, Params},
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sha3::digest::generic_array::{
    GenericArray,
    sequence::Split,
    typenum::{U12, U20},
};

use super::{
    to_hex::ToHex,
    types::zil::{
        self, BlockchainInfo, DSBlock, DSBlockHeaderVerbose, DSBlockListing, DSBlockListingResult,
        DSBlockRateResult, DSBlockVerbose, GetCurrentDSCommResult, MinerInfo, ReceiptResponse,
        RecentTransactionsResponse, SWInfo, ShardingStructure, SmartContract, StateProofResponse,
        TXBlockRateResult, TransactionBody, TransactionState, TransactionStatusResponse,
        TxBlockListing, TxBlockListingResult, TxnBodiesForTxBlockExResponse,
        TxnsForTxBlockExResponse,
    },
};
use crate::{
    api::{
        HandlerType, disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook,
        rpc_base_attributes,
        types::zil::{CreateTransactionResponse, GetTxResponse, RPCErrorCode},
    },
    cfg::EnabledApi,
    crypto::Hash,
    data_access,
    db::Db,
    exec::zil_contract_address,
    message::Block,
    node::Node,
    pool::{PendingOrQueued, TxAddResult},
    schnorr,
    scilla::{ParamValue, split_storage_key, storage_key},
    state::Code,
    time::SystemTime,
    transaction::{
        EVM_GAS_PER_SCILLA_GAS, EvmGas, ScillaGas, SignedTransaction, TxZilliqa, ValidationOutcome,
        ZilAmount,
    },
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("CreateTransaction", create_transaction, HandlerType::Fast),
            (
                "GetContractAddressFromTransactionID",
                get_contract_address_from_transaction_id,
                HandlerType::Fast
            ),
            ("GetBlockchainInfo", get_blockchain_info, HandlerType::Fast),
            ("GetNumTxBlocks", get_num_tx_blocks, HandlerType::Fast),
            (
                "GetSmartContractState",
                get_smart_contract_state,
                HandlerType::Slow
            ),
            (
                "GetSmartContractCode",
                get_smart_contract_code,
                HandlerType::Fast
            ),
            (
                "GetSmartContractInit",
                get_smart_contract_init,
                HandlerType::Fast
            ),
            ("GetTransaction", get_transaction, HandlerType::Fast),
            ("GetBalance", get_balance, HandlerType::Fast),
            (
                "GetCurrentMiniEpoch",
                get_current_mini_epoch,
                HandlerType::Fast
            ),
            ("GetLatestTxBlock", get_latest_tx_block, HandlerType::Fast),
            (
                "GetMinimumGasPrice",
                get_minimum_gas_price,
                HandlerType::Fast
            ),
            ("GetNetworkId", get_network_id, HandlerType::Fast),
            ("GetVersion", get_version, HandlerType::Fast),
            (
                "GetTransactionsForTxBlock",
                get_transactions_for_tx_block,
                HandlerType::Fast
            ),
            ("GetTxBlock", get_tx_block, HandlerType::Fast),
            ("GetTxBlockVerbose", get_tx_block_verbose, HandlerType::Fast),
            ("GetSmartContracts", get_smart_contracts, HandlerType::Fast),
            ("GetDSBlock", get_ds_block, HandlerType::Fast),
            ("GetDSBlockVerbose", get_ds_block_verbose, HandlerType::Fast),
            ("GetLatestDSBlock", get_latest_ds_block, HandlerType::Fast),
            ("GetCurrentDSComm", get_current_ds_comm, HandlerType::Fast),
            ("GetCurrentDSEpoch", get_current_ds_epoch, HandlerType::Fast),
            ("DSBlockListing", ds_block_listing, HandlerType::Fast),
            ("GetDSBlockRate", get_ds_block_rate, HandlerType::Fast),
            ("GetTxBlockRate", get_tx_block_rate, HandlerType::Fast),
            ("TxBlockListing", tx_block_listing, HandlerType::Fast),
            ("GetNumPeers", get_num_peers, HandlerType::Fast),
            ("GetTransactionRate", get_tx_rate, HandlerType::Fast),
            (
                "GetTransactionsForTxBlockEx",
                get_transactions_for_tx_block_ex,
                HandlerType::Fast
            ),
            (
                "GetTxnBodiesForTxBlock",
                get_txn_bodies_for_tx_block,
                HandlerType::Fast
            ),
            (
                "GetTxnBodiesForTxBlockEx",
                get_txn_bodies_for_tx_block_ex,
                HandlerType::Fast
            ),
            ("GetNumDSBlocks", get_num_ds_blocks, HandlerType::Fast),
            (
                "GetRecentTransactions",
                get_recent_transactions,
                HandlerType::Fast
            ),
            (
                "GetNumTransactions",
                get_num_transactions,
                HandlerType::Fast
            ),
            (
                "GetNumTxnsTXEpoch",
                get_num_txns_tx_epoch,
                HandlerType::Fast
            ),
            (
                "GetNumTxnsDSEpoch",
                get_num_txns_ds_epoch,
                HandlerType::Fast
            ),
            (
                "GetTotalCoinSupply",
                get_total_coin_supply,
                HandlerType::Fast
            ),
            (
                "GetTotalCoinSupplyAsInt",
                get_total_coin_supply_as_int,
                HandlerType::Fast
            ),
            ("GetMinerInfo", get_miner_info, HandlerType::Fast),
            ("GetNodeType", get_node_type, HandlerType::Fast),
            ("GetPrevDifficulty", get_prev_difficulty, HandlerType::Fast),
            (
                "GetPrevDSDifficulty",
                get_prev_ds_difficulty,
                HandlerType::Fast
            ),
            (
                "GetShardingStructure",
                get_sharding_structure,
                HandlerType::Fast
            ),
            (
                "GetSmartContractSubState",
                get_smart_contract_sub_state,
                HandlerType::Slow
            ),
            (
                "GetSoftConfirmedTransaction",
                get_soft_confirmed_transaction,
                HandlerType::Fast
            ),
            ("GetStateProof", get_state_proof, HandlerType::Fast),
            (
                "GetTransactionStatus",
                get_transaction_status,
                HandlerType::Fast
            ),
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
fn create_transaction(params: Params, node: &Arc<Node>) -> Result<CreateTransactionResponse> {
    let transaction: TransactionParams = params.one()?;

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
            format!("Cannot extract signature - {err}"),
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

    let Ok(transaction) = signed_transaction.verify() else {
        Err(ErrorObject::owned::<String>(
            RPCErrorCode::RpcVerifyRejected as i32,
            "signature",
            None,
        ))?
    };
    let (transaction_hash, result) = node.create_transaction(transaction)?;
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
fn get_contract_address_from_transaction_id(params: Params, node: &Arc<Node>) -> Result<String> {
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let (receipt, signed_transaction) = {
        let receipt = node
            .get_transaction_receipt(hash)?
            .ok_or_else(|| anyhow!("Txn Hash not Present"))?;
        let signed_transaction = node
            .get_transaction_by_hash(hash)?
            .ok_or_else(|| anyhow!("Txn Hash not Present"))?;
        (receipt, signed_transaction)
    };

    let contract_address = receipt
        .contract_address
        .ok_or_else(|| anyhow!("ID is not a contract txn"))?;

    let contract_address = match signed_transaction.tx {
        SignedTransaction::Zilliqa { tx, .. } => {
            tx.get_contract_address(&signed_transaction.signer)?
        }
        _ => contract_address,
    };

    Ok(contract_address.to_hex_no_prefix())
}

// GetTransaction
fn get_transaction(params: Params, node: &Arc<Node>) -> Result<GetTxResponse> {
    let jsonrpc_error_data: Option<String> = None;
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let db = node.db.clone();

    let tx = data_access::get_transaction_by_hash(db.clone(), None, hash)?.ok_or_else(|| {
        ErrorObject::owned(
            RPCErrorCode::RpcDatabaseError as i32,
            "Txn Hash not Present".to_string(),
            jsonrpc_error_data.clone(),
        )
    })?;
    let receipt = data_access::get_transaction_receipt(db.clone(), hash)?.ok_or_else(|| {
        jsonrpsee::types::ErrorObject::owned(
            RPCErrorCode::RpcDatabaseError as i32,
            "Txn Hash not Present".to_string(),
            jsonrpc_error_data.clone(),
        )
    })?;
    let block = data_access::get_block_by_hash(db.clone(), &receipt.block_hash)?
        .ok_or_else(|| anyhow!("block does not exist"))?;
    if block.number() > data_access::get_finalized_height(db)? {
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
fn get_balance(params: Params, node: &Arc<Node>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let state = {
        let block = node
            .get_block(BlockId::finalized())?
            .ok_or_else(|| anyhow!("Unable to get finalized block!"))?;

        node.get_state(&block)?
    };

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
fn get_current_mini_epoch(_: Params, node: &Arc<Node>) -> Result<String> {
    Ok(node.get_finalized_block_number()?.to_string())
}

// GetLatestTxBlock
fn get_latest_tx_block(_: Params, node: &Arc<Node>) -> Result<zil::TxBlock> {
    let (block, db) = {
        let block = node
            .get_block(BlockId::finalized())?
            .ok_or_else(|| anyhow!("no finalized blocks"))?;
        (block, node.db.clone())
    };

    let txn_fees = get_txn_fees_for_block(db, block.hash())?;
    let tx_block: zil::TxBlock = zil::TxBlock::new(&block, txn_fees);
    Ok(tx_block)
}

// GetMinimumGasPrice
fn get_minimum_gas_price(_: Params, node: &Arc<Node>) -> Result<String> {
    let price = node.get_gas_price();
    // `price` is the cost per unit of [EvmGas]. This API should return the cost per unit of [ScillaGas].
    let price = price * (EVM_GAS_PER_SCILLA_GAS as u128);

    Ok(ZilAmount::from_amount(price).to_string())
}

// GetNetworkId
fn get_network_id(_: Params, node: &Arc<Node>) -> Result<String> {
    let network_id = node.chain_id.zil();
    Ok(network_id.to_string())
}

// GetVersion
fn get_version(_: Params, _: &Arc<Node>) -> Result<Value> {
    let commit = env!("VERGEN_GIT_SHA");
    let version = env!("VERGEN_GIT_DESCRIBE");
    Ok(json!({
        "Commit": commit,
        "Version": version,
    }))
}

// GetBlockchainInfo
fn get_blockchain_info(_: Params, node: &Arc<Node>) -> Result<BlockchainInfo> {
    let transaction_rate = get_tx_rate(Params::new(None), node)?;
    let tx_block_rate = calculate_tx_block_rate(node)?;
    let sharding_structure = get_sharding_structure(Params::new(None), node)?;

    let (num_peers, db) = {
        let num_peers = node.get_peer_num();
        (num_peers, node.db.clone())
    };

    let num_tx_blocks = data_access::get_finalized_block_number(db.clone())?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    let num_transactions = data_access::get_num_transactions(db.clone())?;
    let ds_block_rate = tx_block_rate / TX_BLOCKS_PER_DS_BLOCK as f64;

    // num_txns_ds_epoch
    let current_epoch = num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK;
    let current_epoch_first = current_epoch * TX_BLOCKS_PER_DS_BLOCK;
    let mut num_txns_ds_epoch = 0;
    for i in current_epoch_first..num_tx_blocks {
        let block = data_access::get_block_by_number(db.clone(), i)?
            .ok_or_else(|| anyhow!("Block not found"))?;
        num_txns_ds_epoch += block.transactions.len();
    }

    // num_txns_tx_epoch
    let finalized_block = data_access::get_finalized_block(db.clone())?;
    let num_txns_tx_epoch = match finalized_block {
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
fn get_num_tx_blocks(_: Params, node: &Arc<Node>) -> Result<String> {
    Ok(node.get_finalized_block_number()?.to_string())
}

// GetSmartContractState
fn get_smart_contract_state(params: Params, node: &Arc<Node>) -> Result<Value> {
    let mut seq = params.sequence();
    let address: ZilAddress = seq.next()?;
    let address: Address = address.into();

    if node
        .config
        .api_limits
        .disable_get_full_state_for_contracts
        .contains(&address)
    {
        return Err(anyhow!(
            "GetSmartContractState is disabled for contract address: {}",
            hex::encode(address.0)
        ));
    }

    let (state, state_rpc_limit) = {
        // First get the account and check that it's a scilla account
        let block = node
            .get_block(BlockId::finalized())?
            .ok_or_else(|| anyhow!("Unable to get finalized block!"))?;

        let state = node.get_state(&block)?;
        (state, node.config.api_limits.state_rpc_limit)
    };
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
        let trie = state.get_account_trie(address)?;
        for (i, (k, v)) in trie.iter().flatten().enumerate() {
            if i >= state_rpc_limit {
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

        // Insert empty maps to the state. Empty maps are not returned by the trie iterator.
        let field_defs = match &account.code {
            Code::Scilla { types, .. } => types,
            _ => unreachable!(),
        };
        for (var_name, (type_, _)) in field_defs.iter() {
            if type_.starts_with("Map") {
                result
                    .entry(var_name)
                    .or_insert(Value::Object(Default::default()));
            }
        }
    }
    Ok(result.into())
}

// GetSmartContractCode
fn get_smart_contract_code(params: Params, node: &Arc<Node>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let state = {
        let block = node
            .get_block(BlockId::finalized())?
            .ok_or_else(|| anyhow!("Unable to get the finalized block!"))?;
        node.get_state(&block)?
    };

    if !state.has_account(address)? {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            format!("Address does not exist: {address}"),
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
fn get_smart_contract_init(params: Params, node: &Arc<Node>) -> Result<Vec<ParamValue>> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let state = {
        let block = node
            .get_block(BlockId::finalized())?
            .ok_or_else(|| anyhow!("Unable to get the finalized block!"))?;

        node.get_state(&block)?
    };

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
fn get_transactions_for_tx_block(params: Params, node: &Arc<Node>) -> Result<Vec<Vec<String>>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    let Some(block) = ({ node.get_block(block_number)? }) else {
        return Err(anyhow!("Tx Block does not exist"));
    };

    if block.transactions.is_empty() {
        return Err(anyhow!("TxBlock has no transactions"));
    }

    Ok(vec![
        block
            .transactions
            .into_iter()
            .map(|h| B256::from(h).to_hex_no_prefix())
            .collect(),
    ])
}

pub const TRANSACTIONS_PER_PAGE: usize = 2500;
pub const TX_BLOCKS_PER_DS_BLOCK: u64 = 100;

// GetTxBlock
fn get_tx_block(params: Params, node: &Arc<Node>) -> Result<Option<zil::TxBlock>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let (block, db) = {
        let Some(block) = node.get_block(block_number)? else {
            return Ok(None);
        };
        if block.number() > node.get_finalized_height()? {
            return Err(anyhow!("Block not finalized"));
        }

        (block, node.db.clone())
    };

    let txn_fees = get_txn_fees_for_block(db, block.hash())?;
    let block: zil::TxBlock = zil::TxBlock::new(&block, txn_fees);

    Ok(Some(block))
}

fn get_txn_fees_for_block(db: Arc<Db>, hash: Hash) -> Result<EvmGas> {
    Ok(db
        .get_transaction_receipts_in_block(&hash)?
        .iter()
        .fold(EvmGas(0), |acc, txnrcpt| acc + txnrcpt.gas_used))
}

// GetTxBlockVerbose
fn get_tx_block_verbose(params: Params, node: &Arc<Node>) -> Result<Option<zil::TxBlockVerbose>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let (block, proposer, db) = {
        let Some(block) = node.get_block(block_number)? else {
            return Ok(None);
        };
        if block.number() > node.get_finalized_height()? {
            return Err(anyhow!("Block not finalized"));
        }
        let proposer = node
            .get_proposer_reward_address(&block)?
            .expect("No proposer");
        (block, proposer, node.db.clone())
    };
    let txn_fees = get_txn_fees_for_block(db, block.hash())?;
    let block: zil::TxBlockVerbose = zil::TxBlockVerbose::new(&block, txn_fees, proposer);

    Ok(Some(block))
}

// GetSmartContracts
fn get_smart_contracts(params: Params, node: &Arc<Node>) -> Result<Vec<SmartContract>> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let state = {
        let block = node
            .get_finalized_block()?
            .ok_or_else(|| anyhow!("Unable to get the finalized block!"))?;

        node.get_state(&block)?
    };

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

        let is_scilla = state
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
        cs1: String::from(
            "FBA696961142862169D03EED67DD302EAB91333CBC4EEFE7EDB230515DA31DC1B9746EEEE5E7C105685E22C483B1021867B3775D30215CA66D5D81543E9FE8B5",
        ),
        prev_dshash: String::from(
            "585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e",
        ),
        header: DSBlockHeaderVerbose {
            block_num: dsblocknum.to_string(),
            committee_hash: String::from(
                "da38b3b21b26b71835bb1545246a0a248f97003de302ae20d70aeaf854403029",
            ),
            difficulty: 95,
            difficulty_ds: 156,
            epoch_num: txblocknum.to_string(),
            gas_price: String::from("2000000000"),
            members_ejected: vec![],
            po_wwinners: vec![],
            po_wwinners_ip: vec![],
            prev_hash: String::from(
                "585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e",
            ),
            reserved_field: String::from(
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            swinfo: SWInfo {
                scilla: vec![],
                zilliqa: vec![],
            },
            sharding_hash: String::from(
                "3216a33bfd4801e1907e72c7d529cef99c38d57cd281d0e9d726639fd9882d25",
            ),
            timestamp: String::from("1606443830834512"),
            version: 2,
        },
        signature: String::from(
            "7EE023C56602A17F2C8ABA2BEF290386D7C2CE1ABD8E3621573802FA67B243DE60B3EBEE5C4CCFDB697C80127B99CB384DAFEB44F70CD7569F2816DB950877BB",
        ),
    }
}

fn get_example_ds_block(dsblocknum: u64, txblocknum: u64) -> DSBlock {
    get_example_ds_block_verbose(dsblocknum, txblocknum).into()
}

// GetDSBlock
pub fn get_ds_block(params: Params, _node: &Arc<Node>) -> Result<DSBlock> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

// GetDSBlockVerbose
pub fn get_ds_block_verbose(params: Params, _node: &Arc<Node>) -> Result<DSBlockVerbose> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block_verbose(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

// GetLatestDSBlock
pub fn get_latest_ds_block(_params: Params, node: &Arc<Node>) -> Result<DSBlock> {
    // Dummy implementation
    let db = node.db.clone();
    let num_tx_blocks = data_access::get_finalized_block_number(db)?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(get_example_ds_block(num_ds_blocks, num_tx_blocks))
}

// GetCurrentDSComm
pub fn get_current_ds_comm(_params: Params, node: &Arc<Node>) -> Result<GetCurrentDSCommResult> {
    // Dummy implementation
    let num_tx_blocks = node.get_finalized_block_number()?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(GetCurrentDSCommResult {
        current_dsepoch: num_ds_blocks.to_string(),
        current_tx_epoch: num_tx_blocks.to_string(),
        num_of_dsguard: 420,
        dscomm: vec![],
    })
}

// GetCurrentDSEpoch
pub fn get_current_ds_epoch(_params: Params, node: &Arc<Node>) -> Result<String> {
    // Dummy implementation
    let db = node.db.clone();
    let num_tx_blocks = data_access::get_finalized_block_number(db)?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(num_ds_blocks.to_string())
}

// DSBlockListing
pub fn ds_block_listing(params: Params, node: &Arc<Node>) -> Result<DSBlockListingResult> {
    // Dummy implementation
    let num_tx_blocks = node.get_finalized_block_number()?;

    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK)
        + if num_tx_blocks % TX_BLOCKS_PER_DS_BLOCK == 0 {
            0
        } else {
            1
        };
    let max_pages = num_ds_blocks / 10
        + if num_ds_blocks.is_multiple_of(10) {
            0
        } else {
            1
        };
    let page_requested: u64 = params.one()?;

    if page_requested == 0 || page_requested > max_pages {
        return Err(anyhow!(format!(
            "Page out of range. Valid range is 1 to {max_pages}",
        )));
    }

    let end_blocknum = num_ds_blocks - ((page_requested - 1) * 10);
    let base_blocknum = end_blocknum.saturating_sub(10);
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

// utility function to calculate the tx block rate for get_ds_block_rate and get_tx_block_rate
pub fn calculate_tx_block_rate(node: &Arc<Node>) -> Result<f64> {
    let db = node.db.clone();
    let max_measurement_blocks = 5;
    let height = data_access::get_finalized_block_number(db.clone())?;
    if height == 0 {
        return Ok(0.0);
    }
    let measurement_blocks = height.min(max_measurement_blocks);
    let start_measure_block =
        data_access::get_block_by_number(db, height - measurement_blocks + 1)?
            .ok_or(anyhow!("Unable to get block"))?;
    let start_measure_time = start_measure_block.header.timestamp;
    let end_measure_time = SystemTime::now();
    let elapsed_time = end_measure_time.duration_since(start_measure_time)?;
    let tx_block_rate = measurement_blocks as f64 / elapsed_time.as_secs_f64();
    Ok(tx_block_rate)
}

// GetDSBlockRate
pub fn get_ds_block_rate(_params: Params, node: &Arc<Node>) -> Result<DSBlockRateResult> {
    let tx_block_rate = calculate_tx_block_rate(node)?;
    let ds_block_rate = tx_block_rate / TX_BLOCKS_PER_DS_BLOCK as f64;
    Ok(DSBlockRateResult {
        rate: ds_block_rate,
    })
}

// GetTxBlockRate
fn get_tx_block_rate(_params: Params, node: &Arc<Node>) -> Result<TXBlockRateResult> {
    let tx_block_rate = calculate_tx_block_rate(node)?;
    Ok(TXBlockRateResult {
        rate: tx_block_rate,
    })
}

// TxBlockListing
fn tx_block_listing(params: Params, node: &Arc<Node>) -> Result<TxBlockListingResult> {
    let page_number: u64 = params.one()?;

    let db = node.db.clone();
    let num_tx_blocks = data_access::get_finalized_block_number(db.clone())?;
    let max_pages = (num_tx_blocks / 10) + if num_tx_blocks % 10 == 0 { 0 } else { 1 };

    if page_number == 0 || page_number > max_pages {
        return Err(anyhow!(format!(
            "Page out of range. Valid range is 1 to {max_pages}",
        )));
    }

    let end_block = num_tx_blocks - ((page_number - 1) * 10);
    let start_block = end_block.saturating_sub(10);

    let listings: Vec<TxBlockListing> = (start_block..end_block)
        .rev()
        .filter_map(|block_number| {
            data_access::get_block_by_number(db.clone(), block_number)
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
        max_pages,
    })
}

// GetNumPeers
fn get_num_peers(_params: Params, node: &Arc<Node>) -> Result<u64> {
    let num_peers = node.get_peer_num();
    Ok(num_peers as u64)
}

// GetTransactionRate
// Calculates transaction rate over the most recent block
fn get_tx_rate(_params: Params, node: &Arc<Node>) -> Result<f64> {
    let db = node.db.clone();
    let head_block_num = data_access::get_finalized_block_number(db.clone())?;
    if head_block_num <= 1 {
        return Ok(0.0);
    }
    let prev_block_num = head_block_num - 1;
    let head_block = data_access::get_block_by_number(db.clone(), head_block_num)?
        .ok_or(anyhow!("Unable to get block"))?;
    let prev_block = data_access::get_block_by_number(db, prev_block_num)?
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
    node: &Arc<Node>,
) -> Result<TxnsForTxBlockExResponse> {
    let mut seq = params.sequence();
    let block_number: String = seq.next()?;
    let page_number: String = seq.next()?;
    let block_number: u64 = block_number.parse()?;
    let page_number: usize = page_number.parse()?;

    let db = node.db.clone();
    let block = data_access::get_block_by_number(db.clone(), block_number)?
        .ok_or_else(|| anyhow!("Block not found"))?;
    if block.number() > data_access::get_finalized_height(db.clone())? {
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
fn extract_transaction_bodies(block: &Block, db: Arc<Db>) -> Result<Vec<TransactionBody>> {
    let mut transactions = Vec::with_capacity(block.transactions.len());
    for hash in &block.transactions {
        let tx = data_access::get_transaction_by_hash(db.clone(), None, *hash)?
            .ok_or(anyhow!("Transaction hash missing"))?;
        let nonce = tx.tx.nonce().unwrap_or_default();
        let amount = tx.tx.zil_amount();
        let gas_price = tx.tx.gas_price_per_scilla_gas();
        let gas_limit = tx.tx.gas_limit_scilla();
        let receipt = data_access::get_transaction_receipt(db.clone(), *hash)?
            .ok_or(anyhow!("Transaction receipt missing"))?;
        let receipt_response = ReceiptResponse::new(receipt, block.number());
        let (version, to_addr, sender_pub_key, signature, code, data) = match tx.tx {
            SignedTransaction::Zilliqa { tx, sig, key } => {
                let is_create = !tx.code.is_empty();
                let is_call = !tx.data.is_empty();
                (
                    ((tx.chain_id as u32) << 16) | 1,
                    tx.to_addr,
                    key.to_encoded_point(true).as_bytes().to_hex(),
                    <[u8; 64]>::from(sig.to_bytes()).to_hex(),
                    is_create.then_some(tx.code),
                    is_call.then_some(tx.data),
                )
            }
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
            receipt: receipt_response?,
            sender_pub_key,
            signature,
            to_addr: to_addr.to_string(),
            version: version.to_string(),
            code,
            data,
        };
        transactions.push(body);
    }
    Ok(transactions)
}

// GetTxnBodiesForTxBlock
fn get_txn_bodies_for_tx_block(params: Params, node: &Arc<Node>) -> Result<Vec<TransactionBody>> {
    let params: Vec<String> = params.parse()?;
    let block_number: u64 = params[0].parse()?;

    let db = node.db.clone();
    let block = data_access::get_block_by_number(db.clone(), block_number)?
        .ok_or_else(|| anyhow!("Block not found"))?;

    if block.number() > data_access::get_finalized_height(db.clone())? {
        return Err(anyhow!("Block not finalized"));
    }

    extract_transaction_bodies(&block, db)
}

// GetTxnBodiesForTxBlockEx
fn get_txn_bodies_for_tx_block_ex(
    params: Params,
    node: &Arc<Node>,
) -> Result<TxnBodiesForTxBlockExResponse> {
    let params: Vec<String> = params.parse()?;
    let block_number: u64 = params[0].parse()?;
    let page_number: usize = params[1].parse()?;

    let db = node.db.clone();
    let block = data_access::get_block_by_number(db.clone(), block_number)?
        .ok_or_else(|| anyhow!("Block not found"))?;

    if block.number() > data_access::get_finalized_height(db.clone())? {
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

    let transactions = extract_transaction_bodies(&block, db)?
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
fn get_num_ds_blocks(_params: Params, node: &Arc<Node>) -> Result<String> {
    let db = node.db.clone();
    let num_tx_blocks = data_access::get_finalized_block_number(db)?;
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(num_ds_blocks.to_string())
}

// GetRecentTransactions
fn get_recent_transactions(
    _params: Params,
    node: &Arc<Node>,
) -> Result<RecentTransactionsResponse> {
    let db = node.db.clone();
    let mut block_number = data_access::get_finalized_block_number(db.clone())?;
    let mut txns = Vec::new();
    let mut blocks_searched = 0;
    while block_number > 0 && txns.len() < 100 && blocks_searched < 100 {
        let block = match data_access::get_block_by_number(db.clone(), block_number)? {
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
fn get_num_transactions(_params: Params, node: &Arc<Node>) -> Result<String> {
    let db = node.db.clone();
    let num_transactions = data_access::get_num_transactions(db)?;
    Ok(num_transactions.to_string())
}

// GetNumTxnsTXEpoch
fn get_num_txns_tx_epoch(_params: Params, node: &Arc<Node>) -> Result<String> {
    let db = node.db.clone();
    let finalized_block = data_access::get_finalized_block(db)?;
    let num_transactions = match finalized_block {
        Some(block) => block.transactions.len(),
        None => 0,
    };
    Ok(num_transactions.to_string())
}

// GetNumTxnsDSEpoch
fn get_num_txns_ds_epoch(_params: Params, node: &Arc<Node>) -> Result<String> {
    let db = node.db.clone();
    let ds_epoch_size = TX_BLOCKS_PER_DS_BLOCK;
    let finalized_number = data_access::get_finalized_block_number(db.clone())?;
    let current_epoch = finalized_number / ds_epoch_size;
    let current_epoch_first = current_epoch * ds_epoch_size;
    let mut num_txns_epoch = 0;
    for i in current_epoch_first..finalized_number {
        let block = data_access::get_block_by_number(db.clone(), i)?
            .ok_or_else(|| anyhow!("Block not found"))?;
        num_txns_epoch += block.transactions.len();
    }
    Ok(num_txns_epoch.to_string())
}

// GetTotalCoinSupplyAsZil
fn get_total_coin_supply_as_zil_amount(_params: Params, node: &Arc<Node>) -> Result<ZilAmount> {
    let (state, native_supply) = {
        let native_supply = node.config.consensus.total_native_token_supply.0;
        let finalized_block_number = node
            .get_finalized_block()?
            .ok_or(anyhow!("Cannot find finalized block"))?;
        let state = node.get_state(&finalized_block_number)?;
        (state, native_supply)
    };

    let null_address_balance = state.get_account(Address::ZERO)?.balance;

    Ok(ZilAmount::from_amount(native_supply - null_address_balance))
}

// GetTotalCoinSupply
fn get_total_coin_supply(params: Params, node: &Arc<Node>) -> Result<String> {
    Ok(get_total_coin_supply_as_zil_amount(params, node)?.to_float_string())
}

// GetTotalCoinSupplyAsInt
fn get_total_coin_supply_as_int(params: Params, node: &Arc<Node>) -> Result<u128> {
    Ok(get_total_coin_supply_as_zil_amount(params, node)?.to_zils())
}

// GetMinerInfo
fn get_miner_info(_params: Params, _node: &Arc<Node>) -> Result<MinerInfo> {
    // This endpoint was previously queries by DS block number, which no longer exists, and
    // neither do DS committees, so it now returns placeholder data for all queries to stay ZQ1 compatible.

    Ok(MinerInfo {
        dscommittee: vec![],
        shards: vec![],
    })
}

// GetNodeType
fn get_node_type(_params: Params, _node: &Arc<Node>) -> Result<String> {
    Ok("Seed".into())
}

// GetPrevDifficulty
fn get_prev_difficulty(_params: Params, _node: &Arc<Node>) -> Result<u64> {
    Ok(0)
}

// GetPrevDSDifficulty
fn get_prev_ds_difficulty(_params: Params, _node: &Arc<Node>) -> Result<u64> {
    Ok(0)
}

// GetShardingStructure
fn get_sharding_structure(_params: Params, node: &Arc<Node>) -> Result<ShardingStructure> {
    let num_peers = node.get_peer_num();

    Ok(ShardingStructure {
        num_peers: vec![num_peers as u64],
    })
}

// GetSmartContractSubState
fn get_smart_contract_sub_state(params: Params, node: &Arc<Node>) -> Result<Value> {
    let mut seq = params.sequence();
    let address: ZilAddress = seq.next()?;
    let address: Address = address.into();
    let requested_var_name: &str = match seq.next()? {
        "" => return get_smart_contract_state(params, node),
        x => x,
    };
    let requested_indices: Vec<String> = seq.next()?;

    let (state, node_rpc_limit) = {
        let state_rpc_limit = node.config.api_limits.state_rpc_limit;

        if requested_indices.len() > node.config.api_limits.state_rpc_limit {
            return Err(anyhow!(
                "Requested indices exceed the limit of {}",
                node.config.api_limits.state_rpc_limit
            ));
        }

        // First get the account and check that its a scilla account
        let block = node
            .get_finalized_block()?
            .ok_or_else(|| anyhow!("Unable to get finalized block!"))?;

        let state = node.get_state(&block)?;
        (state, state_rpc_limit)
    };

    if !state.has_account(address)? {
        return Err(ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            "Address does not exist".to_string(),
            None::<()>,
        )
        .into());
    }

    let account = state.get_account(address)?;

    let mut result = serde_json::Map::new();

    if account.code.clone().scilla_code_and_init_data().is_some() {
        let trie = state.get_account_trie(address)?;

        let indicies_encoded = requested_indices
            .iter()
            .map(|x| serde_json::to_vec(&x))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let prefix = storage_key(requested_var_name, &indicies_encoded);
        let mut n = 0;
        for (k, v) in trie.iter_by_prefix(&prefix)?.flatten() {
            n += 1;
            if n > node_rpc_limit {
                return Err(anyhow!(
                    "Requested indices exceed the limit of {node_rpc_limit}",
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

        // If the requested indices are empty, the whole map is likely requested.
        // So, we need to insert an empty map into the sub state because the trie iterator does not return empty maps.
        if requested_indices.is_empty() {
            let field_defs = match &account.code {
                Code::Scilla { types, .. } => types,
                _ => unreachable!(),
            };
            if let Some((var_name, _)) = field_defs.iter().find(|(var_name, (type_, _))| {
                type_.starts_with("Map") && *var_name == requested_var_name
            }) {
                result
                    .entry(var_name)
                    .or_insert(Value::Object(Default::default()));
            }
        }
    }
    if result.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(result.into())
    }
}

// GetSoftConfirmedTransaction
fn get_soft_confirmed_transaction(params: Params, node: &Arc<Node>) -> Result<GetTxResponse> {
    get_transaction(params, node)
}

// GetStateProof
fn get_state_proof(_params: Params, _node: &Arc<Node>) -> Result<StateProofResponse> {
    // State proof isn't meaningful in ZQ2
    Ok(StateProofResponse {
        account_proof: vec![],
        state_proof: vec![],
    })
}

// GetTransactionStatus
fn get_transaction_status(params: Params, node: &Arc<Node>) -> Result<TransactionStatusResponse> {
    let jsonrpc_error_data: Option<String> = None;
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let transaction =
        node.get_transaction_by_hash(hash)?
            .ok_or(jsonrpsee::types::ErrorObject::owned(
                RPCErrorCode::RpcDatabaseError as i32,
                "Txn Hash not found".to_string(),
                jsonrpc_error_data.clone(),
            ))?;
    let receipt = node.get_transaction_receipt(hash)?;

    let (block, success) = if let Some(receipt) = &receipt {
        (node.get_block(receipt.block_hash)?, receipt.success)
    } else {
        (None, false)
    };

    // Determine transaction state
    let state = if receipt.is_some_and(|receipt| !receipt.errors.is_empty()) {
        TransactionState::Error
    } else {
        match &block {
            Some(block) => match node.resolve_block_number(BlockNumberOrTag::Finalized)? {
                Some(x) if x.number() >= block.number() => TransactionState::Finalized,
                _ => TransactionState::Pending,
            },
            None => match node.consensus.read().get_pending_or_queued(&transaction)? {
                Some(PendingOrQueued::Pending) => TransactionState::Pending,
                Some(PendingOrQueued::Queued) => TransactionState::Queued,
                None => panic!("Transaction not found in block or pending/queued"),
            },
        }
    };

    TransactionStatusResponse::new(transaction, success, block, state)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_hex_checksum() {
        use alloy::primitives::{Address, address};

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
