use std::collections::BTreeMap;

use alloy::{
    consensus::SignableTransaction,
    primitives::{Address, B256, B512},
};
use anyhow::Result;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::{hex, hex_no_prefix, option_hex_no_prefix};
use crate::{
    api::{
        to_hex::ToHex,
        zilliqa::{TRANSACTIONS_PER_PAGE, TX_BLOCKS_PER_DS_BLOCK},
    },
    exec::ScillaException,
    message::Block,
    schnorr,
    scilla::ParamValue,
    serde_util::num_as_str,
    time::SystemTime,
    transaction::{
        EvmGas, ScillaGas, SignedTransaction, TransactionReceipt, VerifiedTransaction, ZilAmount,
    },
};

#[derive(Clone, Serialize)]
pub struct TxBlock {
    pub header: TxBlockHeader,
    pub body: TxBlockBody,
}

impl TxBlock {
    pub fn new(block: &Block, txn_fees: EvmGas) -> Self {
        TxBlock {
            header: TxBlockHeader {
                version: 1,                                    // To match ZQ1
                gas_limit: ScillaGas::from(block.gas_limit()), // In Scilla
                gas_used: ScillaGas::from(block.gas_used()),   // In Scilla
                rewards: 0,
                txn_fees,
                prev_block_hash: block.parent_hash().into(),
                block_num: block.number(),
                timestamp: block
                    .timestamp()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros(),
                mb_info_hash: B256::ZERO, // Obsolete in ZQ2
                state_root_hash: block.state_root_hash().into(),
                state_delta_hash: B256::ZERO, // Obsolete in ZQ2
                num_txns: block.transactions.len() as u64,
                num_pages: if block.transactions.is_empty() {
                    0
                } else {
                    (block.transactions.len() / TRANSACTIONS_PER_PAGE) + 1
                },
                num_micro_blocks: 0, // Microblocks obsolete in ZQ2
                ds_block_num: (block.number() / TX_BLOCKS_PER_DS_BLOCK) + 1,
            },
            body: TxBlockBody {
                header_sign: B512::ZERO, // Obsolete in ZQ2
                block_hash: block.hash().into(),
                micro_block_infos: vec![],
            },
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockHeader {
    pub version: u8,
    #[serde(with = "num_as_str")]
    pub gas_limit: ScillaGas,
    #[serde(with = "num_as_str")]
    pub gas_used: ScillaGas,
    #[serde(with = "num_as_str")]
    pub rewards: u128,
    #[serde(with = "num_as_str")]
    pub txn_fees: EvmGas,
    #[serde(serialize_with = "hex_no_prefix")]
    pub prev_block_hash: B256,
    #[serde(with = "num_as_str")]
    pub block_num: u64,
    #[serde(with = "num_as_str")]
    pub timestamp: u128,
    #[serde(serialize_with = "hex_no_prefix")]
    pub mb_info_hash: B256,
    #[serde(serialize_with = "hex_no_prefix")]
    pub state_root_hash: B256,
    #[serde(serialize_with = "hex_no_prefix")]
    pub state_delta_hash: B256,
    pub num_txns: u64,
    pub num_pages: usize,
    pub num_micro_blocks: u8,
    #[serde(rename = "DSBlockNum", with = "num_as_str")]
    pub ds_block_num: u64,
}

#[derive(Clone, Serialize)]
pub struct TxBlockVerbose {
    pub header: TxBlockVerboseHeader,
    pub body: TxBlockVerboseBody,
}

impl TxBlockVerbose {
    pub fn new(block: &Block, txn_fees: EvmGas, proposer: Address) -> Self {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        TxBlockVerbose {
            header: TxBlockVerboseHeader {
                non_verbose_header: TxBlockHeader {
                    version: 1,                                    // To match ZQ1
                    gas_limit: ScillaGas::from(block.gas_limit()), // In Scilla
                    gas_used: ScillaGas::from(block.gas_used()),   // In Scilla
                    rewards: 0,
                    txn_fees,
                    prev_block_hash: block.parent_hash().into(),
                    block_num: block.number(),
                    timestamp: block
                        .timestamp()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros(),
                    mb_info_hash: B256::ZERO, // Obsolete in ZQ2
                    state_root_hash: block.state_root_hash().into(),
                    state_delta_hash: B256::ZERO, // Obsolete in ZQ2
                    num_txns: block.transactions.len() as u64,
                    num_pages: if block.transactions.is_empty() {
                        0
                    } else {
                        (block.transactions.len() / TRANSACTIONS_PER_PAGE) + 1
                    },
                    num_micro_blocks: 0, // Microblocks obsolete in ZQ2
                    ds_block_num: (block.number() / TX_BLOCKS_PER_DS_BLOCK) + 1,
                },
                miner_pub_key: proposer,
                committee_hash: Some(B256::ZERO),
            },
            body: TxBlockVerboseBody {
                header_sign: B512::ZERO, // Obsolete in ZQ2
                block_hash: block.hash().into(),
                micro_block_infos: vec![],
                cosig_bitmap_1: vec![true; 8],
                cosig_bitmap_2: vec![true; 8],
                cosig_1: Some(schnorr::Signature::from_scalars(scalar, scalar).unwrap()),
            },
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockVerboseHeader {
    #[serde(flatten)]
    pub non_verbose_header: TxBlockHeader,
    #[serde(serialize_with = "hex")]
    pub miner_pub_key: Address,
    #[serde(
        serialize_with = "option_hex_no_prefix",
        skip_serializing_if = "Option::is_none"
    )]
    pub committee_hash: Option<B256>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockVerboseBody {
    #[serde(serialize_with = "hex_no_prefix")]
    pub header_sign: B512,
    #[serde(serialize_with = "hex_no_prefix")]
    pub block_hash: B256,
    pub micro_block_infos: Vec<MicroBlockInfo>,
    #[serde(rename = "B1")]
    pub cosig_bitmap_1: Vec<bool>,
    #[serde(rename = "B2")]
    pub cosig_bitmap_2: Vec<bool>,
    #[serde(rename = "CS1")]
    pub cosig_1: Option<schnorr::Signature>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetTxResponse {
    #[serde(rename = "ID", serialize_with = "hex_no_prefix")]
    pub id: B256,
    #[serde(with = "num_as_str")]
    pub version: u32,
    #[serde(with = "num_as_str")]
    pub nonce: u64,
    #[serde(serialize_with = "hex_no_prefix")]
    pub to_addr: Address,
    pub sender_pub_key: String,
    #[serde(with = "num_as_str")]
    pub amount: ZilAmount,
    pub signature: String,
    pub receipt: ReceiptResponse,
    #[serde(with = "num_as_str")]
    pub gas_price: ZilAmount,
    #[serde(with = "num_as_str")]
    pub gas_limit: ScillaGas,
    pub code: Option<String>,
    pub data: Option<String>,
}

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CreateTransactionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<Address>,
    pub info: String,
    #[serde(rename = "TranID")]
    pub tran_id: B256,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transition {
    pub addr: Address,
    pub depth: u64,
    pub msg: TransitionMessage,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TransitionMessage {
    #[serde(rename = "_amount", with = "num_as_str")]
    pub amount: ZilAmount,
    #[serde(rename = "_recipient")]
    pub recipient: Address,
    #[serde(rename = "_tag")]
    pub tag: String,
    pub params: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EventLog {
    pub address: Address,
    #[serde(rename = "_eventname")]
    pub event_name: String,
    pub params: Vec<ParamValue>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ReceiptResponse {
    pub accepted: bool,
    #[serde(with = "num_as_str")]
    pub gas_used: ScillaGas,
    #[serde(with = "num_as_str")]
    pub cumulative_gas_used: ScillaGas,
    #[serde(with = "num_as_str")]
    pub cumulative_gas: ScillaGas, // deprecated
    #[serde(with = "num_as_str")]
    pub epoch_num: u64,
    pub transitions: Vec<Transition>,
    pub event_logs: Vec<EventLog>,
    pub errors: BTreeMap<u64, Vec<u64>>,
    pub exceptions: Vec<ScillaException>,
    pub success: bool,
}

impl ReceiptResponse {
    pub fn new(receipt: TransactionReceipt, block_number: u64) -> Result<Self> {
        Ok(Self {
            gas_used: receipt.gas_used.into(),
            cumulative_gas_used: receipt.cumulative_gas_used.into(),
            cumulative_gas: receipt.gas_used.into(), // for historic reasons, deprecated field
            epoch_num: block_number,
            transitions: receipt
                .transitions
                .into_iter()
                .map(|t| {
                    Ok(Transition {
                        addr: t.from,
                        // The depth of transitions from this API start counting from the first contract call, rather
                        // than from the initial EOA. The initial call is not included as a transition, so this should
                        // never underflow.
                        depth: t.depth - 1,
                        msg: TransitionMessage {
                            amount: t.amount,
                            recipient: t.to,
                            tag: t.tag,
                            params: serde_json::from_str(&t.params)?,
                        },
                    })
                })
                .collect::<Result<_>>()?,
            event_logs: receipt
                .logs
                .into_iter()
                .filter_map(|log| log.into_scilla())
                .map(|log| EventLog {
                    address: log.address,
                    event_name: log.event_name,
                    params: log.params,
                })
                .collect(),
            success: receipt.success,
            accepted: receipt.accepted.unwrap_or(false),
            errors: receipt
                .errors
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(|err| err as u64).collect()))
                .collect(),
            exceptions: receipt.exceptions,
        })
    }
}

impl GetTxResponse {
    pub fn new(
        tx: VerifiedTransaction,
        receipt: TransactionReceipt,
        block_number: u64,
    ) -> Result<GetTxResponse> {
        let amount = tx.tx.zil_amount();
        let gas_price = tx.tx.gas_price_per_scilla_gas();
        let gas_limit = tx.tx.gas_limit_scilla();
        // Some of these are returned as all caps in ZQ1, but that should be fine
        let (nonce, version, to_addr, sender_pub_key, signature, code, data) = match tx.tx {
            SignedTransaction::Zilliqa { tx, sig, key } => (
                tx.nonce,
                ((tx.chain_id as u32) << 16) | 1,
                tx.to_addr,
                key.to_encoded_point(true).as_bytes().to_hex(),
                <[u8; 64]>::from(sig.to_bytes()).to_hex(),
                (!tx.code.is_empty()).then_some(tx.code),
                (!tx.data.is_empty()).then_some(tx.data),
            ),
            SignedTransaction::Legacy { tx, sig } => (
                tx.nonce,
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
                tx.nonce,
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
                tx.nonce,
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
                0,
                ((tx.chain_id as u32) << 16) | 20,
                tx.to_addr.unwrap_or_default(),
                String::new(),
                String::new(),
                tx.to_addr.is_none().then(|| hex::encode(&tx.payload)),
                tx.to_addr.is_some().then(|| hex::encode(&tx.payload)),
            ),
        };

        Ok(GetTxResponse {
            id: tx.hash.into(),
            version,
            nonce,
            to_addr,
            sender_pub_key,
            amount,
            signature,
            receipt: ReceiptResponse::new(receipt, block_number)?,
            gas_price,
            gas_limit,
            code,
            data,
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockBody {
    #[serde(serialize_with = "hex_no_prefix")]
    pub header_sign: B512,
    #[serde(serialize_with = "hex_no_prefix")]
    pub block_hash: B256,
    pub micro_block_infos: Vec<MicroBlockInfo>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MicroBlockInfo {
    micro_block_hash: B256,
    micro_block_shard_id: u8,
    micro_block_txn_root_hash: B256,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockchainInfo {
    #[serde(rename = "NumPeers")]
    pub num_peers: u16,
    #[serde(with = "num_as_str", rename = "NumTxBlocks")]
    pub num_tx_blocks: u64,
    #[serde(with = "num_as_str", rename = "NumDSBlocks")]
    pub num_ds_blocks: u64,
    #[serde(with = "num_as_str", rename = "NumTransactions")]
    pub num_transactions: u64,
    #[serde(rename = "TransactionRate")]
    pub transaction_rate: f64,
    #[serde(rename = "TxBlockRate")]
    pub tx_block_rate: f64,
    #[serde(rename = "DSBlockRate")]
    pub ds_block_rate: f64,
    #[serde(with = "num_as_str", rename = "CurrentMiniEpoch")]
    pub current_mini_epoch: u64,
    #[serde(with = "num_as_str", rename = "CurrentDSEpoch")]
    pub current_ds_epoch: u64,
    #[serde(with = "num_as_str", rename = "NumTxnsDSEpoch")]
    pub num_txns_ds_epoch: u64,
    #[serde(with = "num_as_str", rename = "NumTxnsTxEpoch")]
    pub num_txns_tx_epoch: u64,
    #[serde(rename = "ShardingStructure")]
    pub sharding_structure: ShardingStructure,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ShardingStructure {
    #[serde(rename = "NumPeers")]
    pub num_peers: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct SmartContract {
    #[serde(serialize_with = "hex_no_prefix")]
    pub address: Address,
}

#[derive(Clone, Debug)]
pub enum RPCErrorCode {
    // Standard JSON-RPC 2.0 errors
    // RPC_INVALID_REQUEST is internally mapped to HTTP_BAD_REQUEST (400).
    // It should not be used for application-layer errors.
    RpcInvalidRequest = -32600,
    // RPC_METHOD_NOT_FOUND is internally mapped to HTTP_NOT_FOUND (404).
    // It should not be used for application-layer errors.
    RpcMethodNotFound = -32601,
    RpcInvalidParams = -32602,
    // RPC_INTERNAL_ERROR should only be used for genuine errors in bitcoind
    // (for example datadir corruption).
    RpcInternalError = -32603,
    RpcParseError = -32700,

    // General application defined errors
    RpcMiscError = -1,             // std::exception thrown in command handling
    RpcTypeError = -3,             // Unexpected type was passed as parameter
    RpcInvalidAddressOrKey = -5,   // Invalid address or key
    RpcInvalidParameter = -8,      // Invalid, missing or duplicate parameter
    RpcDatabaseError = -20,        // Database error
    RpcDeserializationError = -22, // Error parsing or validating structure in raw format
    RpcVerifyError = -25,          // General error during transaction or block submission
    RpcVerifyRejected = -26,       // Transaction or block was rejected by network rules
    RpcInWarmup = -28,             // Client still warming up
    RpcMethodDeprecated = -32,     // RPC method is deprecated
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DSBlock {
    pub header: DSBlockHeader,
    pub signature: String,
}

impl From<DSBlockVerbose> for DSBlock {
    fn from(verbose_block: DSBlockVerbose) -> Self {
        DSBlock {
            header: DSBlockHeader::from(verbose_block.header),
            signature: verbose_block.signature,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DSBlockHeader {
    #[serde(rename = "BlockNum")]
    pub block_num: String,
    #[serde(rename = "Difficulty")]
    pub difficulty: u64,
    #[serde(rename = "DifficultyDS")]
    pub difficulty_ds: u64,
    #[serde(rename = "GasPrice")]
    pub gas_price: String,
    #[serde(rename = "PoWWinners")]
    pub pow_winners: Vec<String>,
    #[serde(rename = "PrevHash")]
    pub prev_hash: String,
    #[serde(rename = "Timestamp")]
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DSBlockVerbose {
    // Sample fields based on given/expected data structure
    #[serde(rename = "B1")]
    pub b1: Vec<bool>,
    #[serde(rename = "B2")]
    pub b2: Vec<bool>,
    #[serde(rename = "CS1")]
    pub cs1: String,
    #[serde(rename = "PrevDSHash")]
    pub prev_dshash: String,
    pub header: DSBlockHeaderVerbose,
    pub signature: String,
}

impl From<DSBlockHeaderVerbose> for DSBlockHeader {
    fn from(header: DSBlockHeaderVerbose) -> Self {
        DSBlockHeader {
            block_num: header.block_num,
            difficulty: header.difficulty,
            difficulty_ds: header.difficulty_ds,
            gas_price: header.gas_price,
            pow_winners: header.po_wwinners,
            prev_hash: header.prev_hash,
            timestamp: header.timestamp,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DSBlockHeaderVerbose {
    #[serde(rename = "BlockNum")]
    pub block_num: String,
    #[serde(rename = "CommitteeHash")]
    pub committee_hash: String,
    #[serde(rename = "Difficulty")]
    pub difficulty: u64,
    #[serde(rename = "DifficultyDS")]
    pub difficulty_ds: u64,
    #[serde(rename = "EpochNum")]
    pub epoch_num: String,
    #[serde(rename = "GasPrice")]
    pub gas_price: String,
    #[serde(rename = "MembersEjected")]
    pub members_ejected: Vec<String>,
    #[serde(rename = "PoWWinners")]
    pub po_wwinners: Vec<String>,
    #[serde(rename = "PoWWinnersIP")]
    pub po_wwinners_ip: Vec<PoWWinnerIP>,
    #[serde(rename = "PrevHash")]
    pub prev_hash: String,
    #[serde(rename = "ReservedField")]
    pub reserved_field: String,
    #[serde(rename = "SWInfo")]
    pub swinfo: SWInfo,
    #[serde(rename = "ShardingHash")]
    pub sharding_hash: String,
    #[serde(rename = "Timestamp")]
    pub timestamp: String,
    #[serde(rename = "Version")]
    pub version: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PoWWinnerIP {
    #[serde(rename = "IP")]
    pub ip: String,
    pub port: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SWInfo {
    #[serde(rename = "Scilla")]
    pub scilla: Vec<u64>,
    #[serde(rename = "Zilliqa")]
    pub zilliqa: Vec<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetCurrentDSCommResult {
    #[serde(rename = "CurrentDSEpoch")]
    pub current_dsepoch: String,
    #[serde(rename = "CurrentTxEpoch")]
    pub current_tx_epoch: String,
    #[serde(rename = "NumOfDSGuard")]
    pub num_of_dsguard: u32,
    pub dscomm: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DSBlockRateResult {
    pub rate: f64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DSBlockListingResult {
    pub data: Vec<DSBlockListing>,
    #[serde(rename = "maxPages")]
    pub max_pages: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DSBlockListing {
    #[serde(rename = "BlockNum")]
    pub block_num: u64,
    #[serde(rename = "Hash")]
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TXBlockRateResult {
    pub rate: f64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxBlockListing {
    #[serde(rename = "BlockNum")]
    pub block_num: u64,
    #[serde(rename = "Hash")]
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxBlockListingResult {
    pub data: Vec<TxBlockListing>,
    #[serde(rename = "maxPages")]
    pub max_pages: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxnsForTxBlockExResponse {
    #[serde(rename = "CurrPage")]
    pub curr_page: u64,
    #[serde(rename = "NumPages")]
    pub num_pages: u64,
    #[serde(rename = "Transactions")]
    pub transactions: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxnBodiesForTxBlockExResponse {
    #[serde(rename = "CurrPage")]
    pub curr_page: u64,
    #[serde(rename = "NumPages")]
    pub num_pages: u64,
    #[serde(rename = "Transactions")]
    pub transactions: Vec<TransactionBody>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionBody {
    #[serde(rename = "ID")]
    pub id: String,
    pub amount: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    pub nonce: String,
    pub receipt: ReceiptResponse,
    #[serde(rename = "senderPubKey")]
    pub sender_pub_key: String,
    pub signature: String,
    #[serde(rename = "toAddr")]
    pub to_addr: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub data: Option<String>,
}

// From https://github.com/Zilliqa/Zilliqa/blob/master/src/common/TxnStatus.h#L23
#[derive(Serialize_repr, Debug, Deserialize_repr, Clone)]
#[repr(u8)] // Because otherwise it's weird that 255 is a special case
pub enum TxnStatusCode {
    Dispatched = 1,
    Confirmed = 3,
    PresentNonceHigh = 4,
    Error = 255, // MiscError
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct TransactionStatusResponse {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "_id")]
    pub _id: serde_json::Value,
    pub amount: String,
    pub data: String,
    #[serde(rename = "epochInserted")]
    pub epoch_inserted: String,
    #[serde(rename = "epochUpdated")]
    pub epoch_updated: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[serde(rename = "modificationState")]
    pub modification_state: u64,
    pub status: TxnStatusCode,
    pub nonce: String,
    #[serde(rename = "senderAddr")]
    pub sender_addr: String,
    pub signature: String,
    pub success: bool,
    #[serde(rename = "toAddr")]
    pub to_addr: String,
    pub version: String,
}

#[derive(Clone, Copy)]
pub enum TransactionState {
    Queued,
    Pending,
    Finalized,
    Error,
}

impl TransactionStatusResponse {
    pub fn new(
        tx: VerifiedTransaction,
        success: bool,
        block: Option<Block>,
        state: TransactionState,
    ) -> Result<Self> {
        let amount = tx.tx.zil_amount();
        let gas_price = tx.tx.gas_price_per_scilla_gas();
        let gas_limit = tx.tx.gas_limit_scilla();
        let (nonce, version, to_addr, sender_pub_key, signature, _code, data) = match tx.tx {
            SignedTransaction::Zilliqa { tx, sig, key } => (
                tx.nonce,
                ((tx.chain_id as u32) << 16) | 1,
                tx.to_addr,
                key.to_encoded_point(true).as_bytes().to_hex(),
                <[u8; 64]>::from(sig.to_bytes()).to_hex(),
                (!tx.code.is_empty()).then_some(tx.code),
                (!tx.data.is_empty()).then_some(tx.data),
            ),
            SignedTransaction::Legacy { tx, sig } => (
                tx.nonce,
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
                tx.nonce,
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
                tx.nonce,
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
                0,
                ((tx.chain_id as u32) << 16) | 20,
                tx.to_addr.unwrap_or_default(),
                String::new(),
                String::new(),
                tx.to_addr.is_none().then(|| hex::encode(&tx.payload)),
                tx.to_addr.is_some().then(|| hex::encode(&tx.payload)),
            ),
        };
        let (status_code, modification_state) = match state {
            TransactionState::Error => (TxnStatusCode::Error, 2),
            TransactionState::Finalized => (TxnStatusCode::Confirmed, 2),
            TransactionState::Pending => (TxnStatusCode::Dispatched, 1),
            TransactionState::Queued => (TxnStatusCode::PresentNonceHigh, 1),
        };
        let epoch_inserted = if let Some(block) = &block {
            block.number().to_string()
        } else {
            "".to_string()
        };
        let epoch_updated = if let Some(block) = &block {
            block.number().to_string()
        } else {
            "".to_string()
        };
        let last_modified = if let Some(block) = &block {
            block
                .timestamp()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_micros()
                .to_string()
        } else {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_micros()
                .to_string()
        };
        Ok(Self {
            id: tx.hash.to_string(),
            _id: serde_json::Value::Null,
            amount: amount.to_string(),
            data: data.unwrap_or_default(),
            epoch_inserted,
            epoch_updated,
            gas_limit: gas_limit.to_string(),
            gas_price: gas_price.to_string(),
            last_modified,
            modification_state,
            status: status_code,
            nonce: nonce.to_string(),
            sender_addr: sender_pub_key,
            signature,
            success,
            to_addr: to_addr.to_hex(),
            version: version.to_string(),
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RecentTransactionsResponse {
    #[serde(rename = "TxnHashes")]
    pub txn_hashes: Vec<String>,
    pub number: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MinerInfo {
    pub dscommittee: Vec<String>,
    pub shards: Vec<ShardInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShardInfo {
    pub nodes: Vec<String>,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StateProofResponse {
    #[serde(rename = "accountProof")]
    pub account_proof: Vec<String>,
    #[serde(rename = "stateProof")]
    pub state_proof: Vec<String>,
}
