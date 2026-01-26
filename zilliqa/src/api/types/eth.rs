use std::collections::HashMap;

use alloy::{
    consensus::TxEip1559,
    primitives::{Address, B256, U256},
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use super::{bool_as_int, hex, option_hex, vec_hex};
use crate::{
    api::types::ser_display,
    crypto::Hash,
    message::{self, BitArray},
    time::SystemTime,
    transaction::{self, EvmGas, EvmLog},
};

#[derive(Clone, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum HashOrTransaction {
    Hash(B256),
    Transaction(Transaction),
}

#[derive(Clone, Debug, Serialize)]
pub struct QuorumCertificate {
    #[serde(serialize_with = "hex")]
    pub signature: Vec<u8>,
    #[serde(serialize_with = "hex")]
    pub cosigned: BitArray,
    #[serde(serialize_with = "hex")]
    pub view: u64,
    #[serde(serialize_with = "hex")]
    pub block_hash: B256,
}

impl QuorumCertificate {
    pub fn from_qc(qc: &message::QuorumCertificate) -> Self {
        Self {
            signature: qc.signature.to_bytes(),
            cosigned: qc.cosigned,
            view: qc.view,
            block_hash: qc.block_hash.into(),
        }
    }
}

#[derive(Clone)]
pub enum ErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    // missing or invalid parameters, apparently.
    InvalidInput = -32000,
    ResourceNotFound = -32001,
    ResourceUnavailable = -32002,
    // Transaction creation failed.
    TransactionRejected = -32003,
    MethodNotSupported = -32004,
    LimitExceeded = -32005,
    JSONRPCVersionNotSupported = -32006,
}

#[derive(Clone, Serialize)]
pub struct AggregateQc {
    #[serde(serialize_with = "hex")]
    pub signature: Vec<u8>,
    #[serde(serialize_with = "ser_display")]
    pub cosigned: BitArray,
    #[serde(serialize_with = "hex")]
    pub view: u64,
    pub quorum_certificates: Vec<QuorumCertificate>,
}

impl AggregateQc {
    pub fn from_agg(agg_qc: &Option<message::AggregateQc>) -> Option<Self> {
        agg_qc.as_ref().map(|agg_qc| Self {
            signature: agg_qc.signature.to_bytes(),
            cosigned: agg_qc.cosigned,
            view: agg_qc.view,
            quorum_certificates: agg_qc.qcs.iter().map(QuorumCertificate::from_qc).collect(),
        })
    }
}

/// A block object, returned by the Ethereum API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(flatten)]
    pub header: Header,
    #[serde(serialize_with = "hex")]
    pub size: u64,
    pub transactions: Vec<HashOrTransaction>,
    pub uncles: Vec<B256>,
    pub quorum_certificate: QuorumCertificate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_quorum_certificate: Option<AggregateQc>,
}

impl Block {
    pub fn from_block(block: &message::Block, miner: Address, block_gas_limit: EvmGas) -> Self {
        Block {
            header: Header::from_header(block.header, miner, block_gas_limit),
            size: block.size() as u64,
            transactions: block
                .transactions
                .iter()
                .map(|h| HashOrTransaction::Hash((*h).into()))
                .collect(),
            uncles: vec![], // Uncles do not exist in ZQ2
            quorum_certificate: QuorumCertificate::from_qc(&block.header.qc),
            aggregate_quorum_certificate: AggregateQc::from_agg(&block.agg),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    #[serde(serialize_with = "hex")]
    pub number: u64,
    #[serde(serialize_with = "hex")]
    pub view: u64,
    #[serde(serialize_with = "hex")]
    pub hash: B256,
    #[serde(serialize_with = "hex")]
    pub parent_hash: B256,
    #[serde(serialize_with = "hex")]
    pub nonce: [u8; 8],
    #[serde(serialize_with = "hex")]
    pub sha_3_uncles: B256, // Uncles do not exist in ZQ2
    #[serde(serialize_with = "hex")]
    pub transactions_root: B256,
    #[serde(serialize_with = "hex")]
    pub state_root: B256,
    #[serde(serialize_with = "hex")]
    pub receipts_root: B256,
    #[serde(serialize_with = "hex")]
    pub miner: Address,
    #[serde(serialize_with = "hex")]
    pub difficulty: u64, // Difficulty does not exist in ZQ2
    #[serde(serialize_with = "hex")]
    pub total_difficulty: u64, // Difficulty does not exist in ZQ2
    #[serde(serialize_with = "hex")]
    pub extra_data: Vec<u8>,
    #[serde(serialize_with = "hex")]
    pub gas_limit: EvmGas,
    #[serde(serialize_with = "hex")]
    pub gas_used: EvmGas,
    #[serde(serialize_with = "hex")]
    pub timestamp: u64,
    #[serde(serialize_with = "hex")]
    pub mix_hash: B256,
    #[serde(serialize_with = "hex")]
    pub logs_bloom: [u8; 256],
    #[serde(serialize_with = "hex")]
    base_fee_per_gas: u64,
}

impl Header {
    pub fn from_header(
        header: message::BlockHeader,
        miner: Address,
        block_gas_limit: EvmGas,
    ) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        Header {
            number: header.number,
            view: header.view,
            hash: header.hash.into(),
            parent_hash: header.qc.block_hash.into(),
            mix_hash: B256::ZERO,
            nonce: [0; 8],
            sha_3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                .parse::<B256>()
                .unwrap(), // Uncles do not exist in ZQ2
            transactions_root: header.transactions_root_hash.into(),
            state_root: header.state_root_hash.into(),
            receipts_root: header.receipts_root_hash.into(),
            miner,
            difficulty: 0,       // Difficulty does not exist in ZQ2
            total_difficulty: 0, // Difficulty does not exist in ZQ2
            extra_data: vec![],
            gas_limit: block_gas_limit,
            gas_used: header.gas_used,
            timestamp: header
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            logs_bloom: [0; 256],
            base_fee_per_gas: 0,
        }
    }
}

/// A transaction object, returned by the Ethereum API.
#[derive(Clone, Serialize, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(serialize_with = "option_hex")]
    pub block_hash: Option<B256>,
    #[serde(serialize_with = "option_hex")]
    pub block_number: Option<u64>,
    #[serde(serialize_with = "hex")]
    pub from: Address,
    #[serde(serialize_with = "hex")]
    pub gas: EvmGas,
    #[serde(serialize_with = "hex")]
    pub gas_price: u128,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "option_hex")]
    pub max_fee_per_gas: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "option_hex")]
    pub max_priority_fee_per_gas: Option<u128>,
    #[serde(serialize_with = "hex")]
    pub hash: B256,
    #[serde(serialize_with = "hex")]
    pub input: Vec<u8>,
    #[serde(serialize_with = "hex")]
    pub nonce: u64,
    #[serde(serialize_with = "option_hex")]
    pub to: Option<Address>,
    #[serde(serialize_with = "option_hex")]
    pub transaction_index: Option<u64>,
    #[serde(serialize_with = "hex")]
    pub value: u128,
    #[serde(serialize_with = "hex")]
    pub v: u64,
    #[serde(serialize_with = "hex")]
    pub r: U256,
    #[serde(serialize_with = "hex")]
    pub s: U256,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "option_hex")]
    pub chain_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<(Address, Vec<B256>)>>,
    #[serde(rename = "type", serialize_with = "hex")]
    pub transaction_type: u64,
}

impl Transaction {
    pub fn new(tx: transaction::VerifiedTransaction, block: Option<message::Block>) -> Self {
        let hash = tx.hash;
        let from = tx.signer;
        let v = tx.tx.sig_v();
        let r = tx.tx.sig_r();
        let s = tx.tx.sig_s();
        let transaction = tx.tx.into_transaction();
        let (gas_price, max_fee_per_gas, max_priority_fee_per_gas) = match transaction {
            transaction::Transaction::Legacy(_)
            | transaction::Transaction::Eip2930(_)
            | transaction::Transaction::Zilliqa(_)
            | transaction::Transaction::Intershard(_) => {
                (transaction.max_fee_per_gas().expect("TODO"), None, None)
            }
            transaction::Transaction::Eip1559(TxEip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            }) => (
                // The `gasPrice` for EIP-1559 transactions should be set to the effective gas price of this transaction,
                // which depends on the block's base fee. We don't yet have a base fee so we just set it to the max fee
                // per gas.
                max_fee_per_gas,
                Some(max_fee_per_gas),
                Some(max_priority_fee_per_gas),
            ),
        };
        let access_list = transaction.access_list().map(|list| {
            list.iter()
                .map(|item| (item.address, item.storage_keys.clone()))
                .collect()
        });

        Transaction {
            block_hash: block.as_ref().map(|b| b.hash().0.into()),
            block_number: block.as_ref().map(|b| b.number()),
            from,
            gas: transaction.gas_limit(),
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            hash: hash.into(),
            input: transaction.payload().to_vec(),
            nonce: transaction.nonce().unwrap_or(u64::MAX),
            to: transaction.to_addr(),
            transaction_index: block
                .map(|b| b.transactions.iter().position(|t| *t == hash).unwrap() as u64),
            value: transaction.amount().expect("TODO"),
            v,
            r,
            s,
            chain_id: transaction.chain_id(),
            access_list,
            transaction_type: transaction.transaction_type(),
        }
    }
}

/// A transaction receipt object, returned by the Ethereum API.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    #[serde(serialize_with = "hex")]
    pub transaction_hash: B256,
    #[serde(serialize_with = "hex")]
    pub transaction_index: u64,
    #[serde(serialize_with = "hex")]
    pub block_hash: B256,
    #[serde(serialize_with = "hex")]
    pub block_number: u64,
    #[serde(serialize_with = "hex")]
    pub from: Address,
    #[serde(serialize_with = "option_hex")]
    pub to: Option<Address>,
    #[serde(serialize_with = "hex")]
    pub cumulative_gas_used: EvmGas,
    #[serde(serialize_with = "hex")]
    pub effective_gas_price: u128,
    #[serde(serialize_with = "hex")]
    pub gas_used: EvmGas,
    #[serde(serialize_with = "option_hex")]
    pub contract_address: Option<Address>,
    pub logs: Vec<Log>,
    #[serde(serialize_with = "hex")]
    pub logs_bloom: [u8; 256],
    #[serde(rename = "type", serialize_with = "hex")]
    pub ty: u64,
    #[serde(serialize_with = "bool_as_int")]
    pub status: bool,
    #[serde(serialize_with = "hex")]
    pub v: u64,
    #[serde(serialize_with = "hex")]
    pub r: U256,
    #[serde(serialize_with = "hex")]
    pub s: U256,
}

/// A transaction receipt object, returned by the Ethereum API.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub removed: bool,
    #[serde(serialize_with = "hex")]
    pub log_index: u64,
    #[serde(serialize_with = "hex")]
    pub transaction_index: u64,
    #[serde(serialize_with = "hex")]
    pub transaction_hash: B256,
    #[serde(serialize_with = "hex")]
    pub block_hash: B256,
    #[serde(serialize_with = "hex")]
    pub block_number: u64,
    #[serde(serialize_with = "hex")]
    pub address: Address,
    #[serde(serialize_with = "hex")]
    pub data: Vec<u8>,
    #[serde(serialize_with = "vec_hex")]
    pub topics: Vec<B256>,
}

impl Log {
    pub fn new(
        log: EvmLog,
        log_index: usize,
        transaction_index: usize,
        transaction_hash: Hash,
        block_number: u64,
        block_hash: Hash,
    ) -> Log {
        Log {
            removed: false,
            log_index: log_index as u64,
            transaction_index: transaction_index as u64,
            transaction_hash: transaction_hash.into(),
            block_hash: block_hash.into(),
            block_number,
            address: log.address,
            data: log.data,
            topics: log.topics,
        }
    }

    pub fn bloom(&self, bloom: &mut [u8; 256]) {
        m3_2048(bloom, self.address.as_slice());
        for topic in &self.topics {
            m3_2048(bloom, topic.as_slice());
        }
    }
}

// Adapted from https://github.com/paradigmxyz/reth/blob/c991a31e0d7bc8415e081d8549311122e7531c77/crates/primitives/src/bloom.rs#L194.
fn m3_2048(bloom: &mut [u8; 256], data: &[u8]) {
    let hash = Keccak256::digest(data);

    for i in [0usize, 2, 4] {
        // Calculate `m` by taking the bottom 11 bits of each pair from the hash. (2 ^ 11) - 1 = 2047.
        let m = (hash[i + 1] as usize + ((hash[i] as usize) << 8)) & 2047;
        // The bit at index `2047 - m` (big-endian) in `bloom` should be set to 1.
        let byte = m / 8;
        let bit = m % 8;
        bloom[255 - byte] |= 1 << bit;
    }
}

/// A type for representing null, a single item or an array of items.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    Null,
    One(T),
    Many(Vec<T>),
}

impl<T: PartialEq> OneOrMany<T> {
    pub fn contains(&self, x: &T) -> bool {
        match self {
            OneOrMany::Null => false,
            OneOrMany::One(item) => item == x,
            OneOrMany::Many(items) => items.contains(x),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            OneOrMany::Null => true,
            OneOrMany::One(_) => false,
            OneOrMany::Many(items) => items.is_empty(),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct TxPoolContent {
    pub pending: HashMap<Address, HashMap<u64, Transaction>>,
    pub queued: HashMap<Address, HashMap<u64, Transaction>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncingMeta {
    pub current_phase: String,
    #[serde(serialize_with = "hex")]
    pub peer_count: usize,
    #[serde(serialize_with = "hex")]
    pub header_downloads: usize,
    #[serde(serialize_with = "hex")]
    pub block_downloads: usize,
    #[serde(serialize_with = "hex")]
    pub buffered_blocks: usize,
    #[serde(serialize_with = "hex")]
    pub empty_count: usize,
    #[serde(serialize_with = "hex")]
    pub retry_count: usize,
    #[serde(serialize_with = "hex")]
    pub error_count: usize,
    #[serde(serialize_with = "hex")]
    pub active_sync_count: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncingStruct {
    #[serde(serialize_with = "hex")]
    pub starting_block: u64,
    #[serde(serialize_with = "hex")]
    pub current_block: u64,
    #[serde(serialize_with = "hex")]
    pub highest_block: u64,
    pub stats: SyncingMeta,
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum SyncingResult {
    Bool(bool),
    Struct(SyncingStruct),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAccountResult {
    pub nonce: u64,
    pub balance: u128,
    pub code_hash: B256,
    pub storage_root: B256,
}

#[cfg(test)]
mod tests {
    use alloy::primitives::B256;

    use super::Log;

    #[test]
    fn test_logs_bloom() {
        // Random example from Ethereum mainnet: https://etherscan.io/tx/0x0d70ebb14d21e085b5e9f68a157f58592147e2606f2b75aa996eb2e1648eab7e.
        let log = Log {
            removed: false,
            log_index: 0,
            transaction_index: 0,
            transaction_hash: B256::ZERO,
            block_hash: B256::ZERO,
            block_number: 0,
            address: "0xdac17f958d2ee523a2206206994597c13d831ec7"
                .parse()
                .unwrap(),
            data: vec![],
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
                "0x0000000000000000000000006113dbc74fa1bb8b39ba8d529cc3e212730ef796"
                    .parse()
                    .unwrap(),
                "0x000000000000000000000000c84eb339b9679c9febb073cb2657fa4bbdc48a9f"
                    .parse()
                    .unwrap(),
            ],
        };

        let expected = hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010002000010020000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000040000000000000000000000000000000000100000010000000001000000000000000000000000000000000000000000000000000000000100000000000000000000000000080000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut actual = [0; 256];
        log.bloom(&mut actual);
        assert_eq!(actual.as_slice(), expected.as_slice());
    }
}
