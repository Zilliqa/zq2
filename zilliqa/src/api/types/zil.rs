use std::collections::BTreeMap;

use primitive_types::{H160, H256, H512};
use serde::Serialize;

use super::{hex, hex_no_prefix};
use crate::{
    exec::{ScillaError, ScillaException},
    message::Block,
    schnorr,
    serde_util::num_as_str,
    time::SystemTime,
    transaction::{ScillaLog, SignedTransaction, TransactionReceipt, VerifiedTransaction},
};

#[derive(Clone, Serialize)]
pub struct TxBlock {
    header: TxBlockHeader,
    body: TxBlockBody,
}

impl From<&Block> for TxBlock {
    fn from(block: &Block) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        TxBlock {
            header: TxBlockHeader {
                block_num: block.number(),
                ds_block_num: (block.number() / 100) + 1,
                gas_limit: 1,
                gas_used: 0,
                mb_info_hash: H256::zero(),
                miner_pub_key: [0; 33],
                num_micro_blocks: 0,
                num_pages: 0,
                num_txns: block.transactions.len() as u64,
                prev_block_hash: H256(block.parent_hash().0),
                rewards: 0,
                state_delta_hash: H256::zero(),
                state_root_hash: H256(block.state_root_hash().0),
                timestamp: block
                    .timestamp()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                txn_fees: 0,
                version: 0,
            },
            body: TxBlockBody {
                block_hash: H256(block.hash().0),
                header_sign: H512::zero(),
                micro_block_infos: vec![],
            },
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
struct TxBlockHeader {
    block_num: u64,
    ds_block_num: u64,
    gas_limit: u64,
    gas_used: u64,
    mb_info_hash: H256,
    #[serde(serialize_with = "hex")]
    miner_pub_key: [u8; 33],
    num_micro_blocks: u8,
    num_pages: u64,
    num_txns: u64,
    prev_block_hash: H256,
    rewards: u64,
    state_delta_hash: H256,
    state_root_hash: H256,
    timestamp: u64,
    txn_fees: u64,
    version: u32,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<bool>,
    #[serde(with = "num_as_str")]
    cumulative_gas: u64,
    #[serde(with = "num_as_str")]
    epoch_num: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    event_logs: Vec<ScillaLog>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    errors: BTreeMap<u64, Vec<u64>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exceptions: Vec<ScillaException>,
    success: bool,
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
                    event_logs: receipt
                        .logs
                        .into_iter()
                        .filter_map(|log| log.into_scilla()) // TODO: Expose EVM logs in Scilla API.
                        .collect(),
                    success: receipt.success,
                    accepted: receipt.accepted,
                    errors: receipt
                        .errors
                        .into_iter()
                        .map(|(k, v)| {
                            (
                                k,
                                v.into_iter()
                                    .map(|err| match err {
                                        ScillaError::CallFailed => 7,
                                        ScillaError::CreateFailed => 8,
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                    exceptions: receipt.exceptions,
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
struct TxBlockBody {
    block_hash: H256,
    header_sign: H512,
    micro_block_infos: Vec<MicroBlockInfo>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
struct MicroBlockInfo {
    micro_block_hash: H256,
    micro_block_shard_id: u8,
    micro_block_txn_root_hash: H256,
}
