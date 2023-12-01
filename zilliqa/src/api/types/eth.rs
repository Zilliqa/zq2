use crate::{
    crypto::Hash,
    state::{default_gas, default_gas_price, Address},
};
use primitive_types::{H160, H256, U256};
use serde::{
    de::{self, Unexpected},
    Deserialize, Deserializer, Serialize,
};
use sha3::{Digest, Keccak256};

use crate::{message, time::SystemTime};

use super::{bool_as_int, hex, option_hex, vec_hex};

#[derive(Clone, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum HashOrTransaction {
    Hash(H256),
    Transaction(Transaction),
}

/// A block object, returned by the Ethereum API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(serialize_with = "hex")]
    pub number: u64,
    #[serde(serialize_with = "hex")]
    pub hash: H256,
    #[serde(serialize_with = "hex")]
    pub parent_hash: H256,
    #[serde(serialize_with = "hex")]
    pub nonce: [u8; 8],
    #[serde(serialize_with = "hex")]
    pub sha_3_uncles: H256,
    #[serde(serialize_with = "hex")]
    pub logs_bloom: [u8; 256],
    #[serde(serialize_with = "hex")]
    pub transactions_root: H256,
    #[serde(serialize_with = "hex")]
    pub state_root: H256,
    #[serde(serialize_with = "hex")]
    pub receipts_root: H256,
    #[serde(serialize_with = "hex")]
    pub miner: H160,
    #[serde(serialize_with = "hex")]
    pub difficulty: u64,
    #[serde(serialize_with = "hex")]
    pub total_difficulty: u64,
    #[serde(serialize_with = "hex")]
    pub extra_data: Vec<u8>,
    #[serde(serialize_with = "hex")]
    pub size: u64,
    #[serde(serialize_with = "hex")]
    pub gas_limit: u64,
    #[serde(serialize_with = "hex")]
    pub gas_used: u64,
    #[serde(serialize_with = "hex")]
    pub timestamp: u64,
    pub transactions: Vec<HashOrTransaction>,
    pub uncles: Vec<H256>,
}

impl From<&message::Block> for Block {
    fn from(block: &message::Block) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        Block {
            number: block.number(),
            hash: H256(block.hash().0),
            parent_hash: H256(block.parent_hash().0),
            nonce: [0; 8],
            sha_3_uncles: H256::zero(),
            logs_bloom: [0; 256],
            transactions_root: H256::zero(),
            state_root: H256(block.state_root_hash().0),
            receipts_root: H256::zero(),
            miner: H160::zero(),
            difficulty: 0,
            total_difficulty: 0,
            extra_data: vec![],
            size: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: block
                .timestamp()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            transactions: block
                .transactions
                .iter()
                .map(|h| HashOrTransaction::Hash(H256(h.0)))
                .collect(),
            uncles: vec![],
        }
    }
}

/// A transaction object, returned by the Ethereum API.
#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(serialize_with = "option_hex")]
    pub block_hash: Option<H256>,
    #[serde(serialize_with = "option_hex")]
    pub block_number: Option<u64>,
    #[serde(serialize_with = "hex")]
    pub from: H160,
    #[serde(serialize_with = "hex")]
    pub gas: u64,
    #[serde(serialize_with = "hex")]
    pub gas_price: u128,
    #[serde(serialize_with = "option_hex")]
    pub max_fee_per_gas: Option<u128>,
    #[serde(serialize_with = "option_hex")]
    pub max_priority_fee_per_gas: Option<u128>,
    #[serde(serialize_with = "hex")]
    pub hash: H256,
    #[serde(serialize_with = "hex")]
    pub input: Vec<u8>,
    #[serde(serialize_with = "hex")]
    pub nonce: u64,
    #[serde(serialize_with = "option_hex")]
    pub to: Option<H160>,
    #[serde(serialize_with = "option_hex")]
    pub transaction_index: Option<u64>,
    #[serde(serialize_with = "hex")]
    pub value: u128,
    #[serde(serialize_with = "hex")]
    pub v: u64,
    #[serde(serialize_with = "hex")]
    pub r: [u8; 32],
    #[serde(serialize_with = "hex")]
    pub s: [u8; 32],
    #[serde(serialize_with = "option_hex")]
    pub chain_id: Option<u64>,
    pub access_list: Option<Vec<(H160, Vec<H256>)>>,
    #[serde(rename = "type", serialize_with = "hex")]
    pub transaction_type: u64,
}

/// A transaction receipt object, returned by the Ethereum API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    #[serde(serialize_with = "hex")]
    pub transaction_hash: H256,
    #[serde(serialize_with = "hex")]
    pub transaction_index: u64,
    #[serde(serialize_with = "hex")]
    pub block_hash: H256,
    #[serde(serialize_with = "hex")]
    pub block_number: u64,
    #[serde(serialize_with = "hex")]
    pub from: H160,
    #[serde(serialize_with = "option_hex")]
    pub to: Option<H160>,
    #[serde(serialize_with = "hex")]
    pub cumulative_gas_used: u64,
    #[serde(serialize_with = "hex")]
    pub effective_gas_price: u64,
    #[serde(serialize_with = "hex")]
    pub gas_used: u64,
    #[serde(serialize_with = "option_hex")]
    pub contract_address: Option<H160>,
    pub logs: Vec<Log>,
    #[serde(serialize_with = "hex")]
    pub logs_bloom: [u8; 256],
    #[serde(serialize_with = "hex")]
    pub ty: u64,
    #[serde(serialize_with = "bool_as_int")]
    pub status: bool,
}

/// A transaction receipt object, returned by the Ethereum API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub removed: bool,
    #[serde(serialize_with = "hex")]
    pub log_index: u64,
    #[serde(serialize_with = "hex")]
    pub transaction_index: u64,
    #[serde(serialize_with = "hex")]
    pub transaction_hash: H256,
    #[serde(serialize_with = "hex")]
    pub block_hash: H256,
    #[serde(serialize_with = "hex")]
    pub block_number: u64,
    #[serde(serialize_with = "hex")]
    pub address: H160,
    #[serde(serialize_with = "hex")]
    pub data: Vec<u8>,
    #[serde(serialize_with = "vec_hex")]
    pub topics: Vec<H256>,
}

impl Log {
    pub fn new(
        log: evm_ds::protos::evm_proto::Log,
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
            transaction_hash: H256(transaction_hash.0),
            block_hash: H256(block_hash.0),
            block_number,
            address: log.address,
            data: log.data,
            topics: log.topics,
        }
    }

    pub fn bloom(&self, bloom: &mut [u8; 256]) {
        m3_2048(bloom, self.address.as_bytes());
        for topic in &self.topics {
            m3_2048(bloom, topic.as_bytes());
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
#[derive(Deserialize, Serialize)]
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

/// Parameters passed to `eth_call`.
#[derive(Deserialize, Serialize)]
pub struct CallParams {
    #[serde(default)]
    pub from: H160,
    pub to: Option<H160>,
    #[serde(deserialize_with = "deserialize_data")]
    pub data: Vec<u8>,
    #[serde(default)]
    pub value: u64,
}

/// Parameters passed to `estimate_gas`.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimateGasParams {
    #[serde(default = "Address::zero")]
    pub from: Address,
    pub to: Option<Address>,
    #[serde(default = "default_gas", deserialize_with = "deserialize_hex_str")]
    pub gas: u64,
    #[serde(
        default = "default_gas_price",
        deserialize_with = "deserialize_hex_str"
    )]
    pub gas_price: u64,
    #[serde(default)]
    pub value: U256,
    #[serde(default, deserialize_with = "deserialize_data")]
    pub data: Vec<u8>,
}

fn deserialize_data<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;

    let s = s.strip_prefix("0x").ok_or_else(|| {
        de::Error::invalid_value(Unexpected::Str(&s), &"a string prefixed with \"0x\"")
    })?;

    hex::decode(s).map_err(de::Error::custom)
}

fn deserialize_hex_str<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let s = String::deserialize(deserializer)?;

    let s = s.strip_prefix("0x").ok_or_else(|| {
        de::Error::invalid_value(Unexpected::Str(&s), &"a string prefixed with \"0x\"")
    })?;

    Ok(u64::from_str_radix(s, 16).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use primitive_types::H256;

    use super::Log;

    #[test]
    fn test_logs_bloom() {
        // Random example from Ethereum mainnet: https://etherscan.io/tx/0x0d70ebb14d21e085b5e9f68a157f58592147e2606f2b75aa996eb2e1648eab7e.
        let log = Log {
            removed: false,
            log_index: 0,
            transaction_index: 0,
            transaction_hash: H256::zero(),
            block_hash: H256::zero(),
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
