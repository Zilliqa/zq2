use primitive_types::{H160, H256, H512};
use serde::Serialize;

use super::{hex, hex_no_prefix, option_hex_no_prefix};
use crate::{
    api::zil::{TRANSACTIONS_PER_PAGE, TX_BLOCKS_PER_DS_BLOCK},
    exec::BLOCK_GAS_LIMIT,
    message::Block,
    schnorr,
    serde_util::num_as_str,
    time::SystemTime,
    transaction::{ScillaLog, SignedTransaction, TransactionReceipt, VerifiedTransaction},
};

#[derive(Clone, Serialize)]
pub struct TxBlock {
    pub header: TxBlockHeader,
    pub body: TxBlockBody,
}

impl From<&Block> for TxBlock {
    fn from(block: &Block) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        TxBlock {
            header: TxBlockHeader {
                version: 0,
                gas_limit: BLOCK_GAS_LIMIT, // TODO: Scale into units of Scilla gas
                gas_used: 0,
                rewards: 0,
                txn_fees: 0,
                prev_block_hash: H256(block.parent_hash().0),
                block_num: block.number(),
                timestamp: block
                    .timestamp()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros(),
                mb_info_hash: H256::zero(),
                state_root_hash: H256(block.state_root_hash().0),
                state_delta_hash: H256::zero(),
                num_txns: block.transactions.len() as u64,
                num_pages: if block.transactions.is_empty() {
                    0
                } else {
                    (block.transactions.len() / TRANSACTIONS_PER_PAGE) + 1
                },
                num_micro_blocks: 0,
                miner_pub_key: [0; 33],
                ds_block_num: (block.number() / TX_BLOCKS_PER_DS_BLOCK) + 1,
                committee_hash: None,
            },
            body: TxBlockBody {
                header_sign: H512::zero(),
                block_hash: H256(block.hash().0),
                micro_block_infos: vec![],
                cosig_bitmap_1: vec![],
                cosig_bitmap_2: vec![],
                cosig_1: None,
            },
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockHeader {
    pub version: u8,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub rewards: u128,
    pub txn_fees: u128,
    #[serde(serialize_with = "hex_no_prefix")]
    pub prev_block_hash: H256,
    #[serde(with = "num_as_str")]
    pub block_num: u64,
    #[serde(with = "num_as_str")]
    pub timestamp: u128,
    #[serde(serialize_with = "hex_no_prefix")]
    pub mb_info_hash: H256,
    #[serde(serialize_with = "hex_no_prefix")]
    pub state_root_hash: H256,
    #[serde(serialize_with = "hex_no_prefix")]
    pub state_delta_hash: H256,
    pub num_txns: u64,
    pub num_pages: usize,
    pub num_micro_blocks: u8,
    #[serde(serialize_with = "hex")]
    pub miner_pub_key: [u8; 33],
    pub ds_block_num: u64,
    #[serde(
        serialize_with = "option_hex_no_prefix",
        skip_serializing_if = "Option::is_none"
    )]
    pub committee_hash: Option<H256>,
}

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetTxResponse {
    #[serde(rename = "ID", serialize_with = "hex_no_prefix")]
    id: H256,
    version: u32,
    #[serde(with = "num_as_str")]
    nonce: u64,
    #[serde(serialize_with = "hex_no_prefix")]
    to_addr: H160,
    sender_pub_key: schnorr::PublicKey,
    #[serde(with = "num_as_str")]
    amount: u128,
    signature: schnorr::Signature,
    receipt: GetTxResponseReceipt,
    #[serde(with = "num_as_str")]
    gas_price: u128,
    #[serde(with = "num_as_str")]
    gas_limit: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CreateTransactionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<H160>,
    pub info: String,
    #[serde(rename = "TranID")]
    pub tran_id: H256,
}

#[derive(Clone, Serialize, Debug)]
struct GetTxResponseReceipt {
    #[serde(with = "num_as_str")]
    cumulative_gas: u64,
    #[serde(with = "num_as_str")]
    epoch_num: u64,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_logs: Option<Vec<ScillaLog>>,
}

impl GetTxResponse {
    pub fn new(
        tx: VerifiedTransaction,
        receipt: TransactionReceipt,
        block_number: u64,
    ) -> Option<Self> {
        let VerifiedTransaction { tx, hash, .. } = tx;
        if let SignedTransaction::Zilliqa { tx, key, sig } = tx {
            Some(GetTxResponse {
                id: H256(hash.0),
                version: ((tx.chain_id as u32) << 16) | 1,
                nonce: tx.nonce,
                to_addr: tx.to_addr,
                sender_pub_key: key,
                amount: tx.amount,
                signature: sig,
                receipt: GetTxResponseReceipt {
                    cumulative_gas: receipt.gas_used,
                    epoch_num: block_number,
                    success: receipt.success,
                    event_logs: (!receipt.logs.is_empty()).then(|| {
                        receipt
                            .logs
                            .into_iter()
                            .filter_map(|log| log.into_scilla()) // TODO: Expose EVM logs in Scilla API.
                            .collect()
                    }),
                },
                gas_price: tx.gas_price,
                gas_limit: tx.gas_limit,
                code: (!tx.code.is_empty()).then_some(tx.code),
                data: (!tx.data.is_empty()).then_some(tx.data),
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockBody {
    #[serde(serialize_with = "hex_no_prefix")]
    pub header_sign: H512,
    #[serde(serialize_with = "hex_no_prefix")]
    pub block_hash: H256,
    pub micro_block_infos: Vec<MicroBlockInfo>,
    #[serde(rename = "B1", skip_serializing_if = "Vec::is_empty")]
    pub cosig_bitmap_1: Vec<bool>,
    #[serde(rename = "B2", skip_serializing_if = "Vec::is_empty")]
    pub cosig_bitmap_2: Vec<bool>,
    #[serde(rename = "CS1", skip_serializing_if = "Option::is_none")]
    pub cosig_1: Option<schnorr::Signature>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MicroBlockInfo {
    micro_block_hash: H256,
    micro_block_shard_id: u8,
    micro_block_txn_root_hash: H256,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockchainInfo {
    pub num_peers: u16,
    #[serde(with = "num_as_str")]
    pub num_tx_blocks: u64,
    #[serde(with = "num_as_str")]
    pub num_ds_blocks: u64,
    #[serde(with = "num_as_str")]
    pub num_transactions: u64,
    pub transaction_rate: f64,
    pub tx_block_rate: f64,
    pub ds_block_rate: f64,
    #[serde(with = "num_as_str")]
    pub current_mini_epoch: u64,
    #[serde(with = "num_as_str")]
    pub current_ds_epoch: u64,
    #[serde(with = "num_as_str")]
    pub num_txns_ds_epoch: u64,
    #[serde(with = "num_as_str")]
    pub num_txns_tx_epoch: u64,
    pub sharding_structure: ShardingStructure,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ShardingStructure {
    pub num_peers: Vec<u16>,
}
