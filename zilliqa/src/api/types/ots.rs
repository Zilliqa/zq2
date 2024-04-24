use primitive_types::{H160, H256};
use serde::Serialize;

use super::{eth, hex, option_hex};
use crate::{message, time::SystemTime};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(serialize_with = "hex")]
    number: u64,
    #[serde(serialize_with = "hex")]
    hash: H256,
    #[serde(serialize_with = "hex")]
    parent_hash: H256,
    #[serde(serialize_with = "hex")]
    nonce: u64,
    #[serde(serialize_with = "hex")]
    sha_3_uncles: H256,
    #[serde(serialize_with = "hex")]
    transactions_root: H256,
    #[serde(serialize_with = "hex")]
    state_root: H256,
    #[serde(serialize_with = "hex")]
    receipts_root: H256,
    #[serde(serialize_with = "hex")]
    miner: H160,
    #[serde(serialize_with = "hex")]
    difficulty: u64,
    #[serde(serialize_with = "hex")]
    total_difficulty: u64,
    #[serde(serialize_with = "hex")]
    extra_data: Vec<u8>,
    #[serde(serialize_with = "hex")]
    size: u64,
    #[serde(serialize_with = "hex")]
    gas_limit: u64,
    #[serde(serialize_with = "hex")]
    gas_used: u64,
    #[serde(serialize_with = "hex")]
    timestamp: u64,
    transaction_count: usize,
    uncles: Vec<H256>,
    #[serde(serialize_with = "hex")]
    base_fee_per_gas: u64,
}

#[derive(Clone, Serialize)]
pub struct BlockWithTransactions {
    #[serde(flatten)]
    pub block: Block,
    pub transactions: Vec<eth::Transaction>,
}

/// A block details object, returned by the Otterscan API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDetails {
    block: Block,
    issuance: BlockIssuance,
    #[serde(serialize_with = "hex")]
    total_fees: u64,
}

impl BlockDetails {
    pub fn from_block(block: &message::Block, miner: H160) -> Self {
        BlockDetails {
            block: Block::from_block(block, miner),
            issuance: BlockIssuance {
                block_reward: 0,
                uncle_reward: 0,
                issuance: 0,
            },
            total_fees: 0,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockIssuance {
    #[serde(serialize_with = "hex")]
    block_reward: u64,
    #[serde(serialize_with = "hex")]
    uncle_reward: u64,
    #[serde(serialize_with = "hex")]
    issuance: u64,
}

impl Block {
    pub fn from_block(block: &message::Block, miner: H160) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        Block {
            number: block.number(),
            hash: H256(block.hash().0),
            parent_hash: H256(block.parent_hash().0),
            nonce: 0,
            sha_3_uncles: H256::zero(),
            transactions_root: H256::zero(),
            state_root: H256(block.state_root_hash().0),
            receipts_root: H256::zero(),
            miner,
            difficulty: 0,
            total_difficulty: 0,
            extra_data: vec![],
            size: 0,
            gas_limit: 1,
            gas_used: 0,
            timestamp: block
                .timestamp()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            transaction_count: block.transactions.len(),
            uncles: vec![],
            base_fee_per_gas: 0,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockTransactions {
    #[serde(rename = "fullblock")]
    pub full_block: BlockWithTransactions,
    pub receipts: Vec<eth::TransactionReceipt>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Transactions {
    #[serde(rename = "txs")]
    pub transactions: Vec<eth::Transaction>,
    pub receipts: Vec<TransactionReceiptWithTimestamp>,
    pub first_page: bool,
    pub last_page: bool,
}

#[derive(Clone, Serialize)]
pub struct TransactionReceiptWithTimestamp {
    #[serde(flatten)]
    pub receipt: eth::TransactionReceipt,
    #[serde(serialize_with = "hex")]
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceEntry {
    #[serde(rename = "type")]
    pub ty: TraceEntryType,
    pub depth: u64,
    #[serde(serialize_with = "hex")]
    pub from: H160,
    #[serde(serialize_with = "hex")]
    pub to: H160,
    #[serde(serialize_with = "option_hex")]
    pub value: Option<u128>,
    #[serde(serialize_with = "hex")]
    pub input: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TraceEntryType {
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
    Create,
    Create2,
    SelfDestruct,
}

#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    #[serde(rename = "type")]
    pub ty: OperationType,
    #[serde(serialize_with = "hex")]
    pub from: H160,
    #[serde(serialize_with = "hex")]
    pub to: H160,
    #[serde(serialize_with = "hex")]
    pub value: u128,
}

#[derive(Debug, Clone)]
pub enum OperationType {
    Transfer,
    SelfDestruct,
    Create,
    Create2,
}

impl Serialize for OperationType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ty: u8 = match self {
            OperationType::Transfer => 0,
            OperationType::SelfDestruct => 1,
            OperationType::Create => 2,
            OperationType::Create2 => 3,
        };
        ty.serialize(serializer)
    }
}
