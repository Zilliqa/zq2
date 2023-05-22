use primitive_types::{H160, H256};
use serde::{
    de::{self, Unexpected},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::message;

use super::to_hex::ToHex;

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum HashOrTransaction {
    Hash(H256),
    Transaction(EthTransaction),
}

/// A block object, returned by the Ethereum API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthBlock {
    #[serde(serialize_with = "hex")]
    pub number: u64,
    #[serde(serialize_with = "hex")]
    pub hash: H256,
    #[serde(serialize_with = "hex")]
    pub parent_hash: H256,
    #[serde(serialize_with = "hex")]
    pub nonce: u64,
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

impl From<&message::Block> for EthBlock {
    fn from(block: &message::Block) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        EthBlock {
            number: block.view(),
            hash: H256(block.hash().0),
            parent_hash: H256(block.parent_hash().0),
            nonce: 0,
            sha_3_uncles: H256::zero(),
            logs_bloom: [0; 256],
            transactions_root: H256::zero(),
            state_root: H256::from_low_u64_be(block.state_root_hash()),
            receipts_root: H256::zero(),
            miner: H160::zero(),
            difficulty: 0,
            total_difficulty: 0,
            extra_data: vec![],
            size: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
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
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransaction {
    #[serde(serialize_with = "hex")]
    pub block_hash: H256,
    #[serde(serialize_with = "hex")]
    pub block_number: u64,
    #[serde(serialize_with = "hex")]
    pub from: H160,
    #[serde(serialize_with = "hex")]
    pub gas: u64,
    #[serde(serialize_with = "hex")]
    pub gas_price: u64,
    #[serde(serialize_with = "hex")]
    pub input: Vec<u8>,
    #[serde(serialize_with = "hex")]
    pub nonce: u64,
    #[serde(serialize_with = "option_hex")]
    pub to: Option<H160>,
    #[serde(serialize_with = "hex")]
    pub transaction_index: u64,
    #[serde(serialize_with = "hex")]
    pub value: u64,
    #[serde(serialize_with = "hex")]
    pub v: u8,
    #[serde(serialize_with = "hex")]
    pub r: [u8; 32],
    #[serde(serialize_with = "hex")]
    pub s: [u8; 32],
}

/// A transaction receipt object, returned by the Ethereum API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransactionReceipt {
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
    #[serde(serialize_with = "hex")]
    pub to: H160,
    #[serde(serialize_with = "hex")]
    pub cumulative_gas_used: u64,
    #[serde(serialize_with = "hex")]
    pub effective_gas_price: u64,
    #[serde(serialize_with = "hex")]
    pub gas_used: u64,
    #[serde(serialize_with = "option_hex")]
    pub contract_address: Option<H160>,
    pub logs: Vec<String>,
    #[serde(serialize_with = "hex")]
    pub logs_bloom: [u8; 256],
    #[serde(serialize_with = "hex")]
    pub ty: u64,
    #[serde(serialize_with = "bool_as_int")]
    pub status: bool,
}

fn hex<S: Serializer, T: ToHex>(data: T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&data.to_hex())
}

fn option_hex<S: Serializer, T: ToHex>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error> {
    if let Some(data) = data {
        serializer.serialize_some(&data.to_hex())
    } else {
        serializer.serialize_none()
    }
}

fn bool_as_int<S: Serializer>(b: &bool, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u8(if *b { 1 } else { 0 })
}

/// Parameters passed to `eth_call`.
#[derive(Deserialize)]
pub struct CallParams {
    // The documentation states that the `to` field is required, but some clients (notably Ethers.js) omit it for
    // contract creations, where the `to` address is zero. Therefore, we default to the zero address if `to` is
    // omitted.
    #[serde(default)]
    pub to: H160,
    #[serde(deserialize_with = "deserialize_data")]
    pub data: Vec<u8>,
}

fn deserialize_data<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;

    let s = s.strip_prefix("0x").ok_or_else(|| {
        de::Error::invalid_value(Unexpected::Str(&s), &"a string prefixed with \"0x\"")
    })?;

    hex::decode(s).map_err(de::Error::custom)
}
