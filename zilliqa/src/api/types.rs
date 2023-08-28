use primitive_types::{H160, H256, U256};
use serde::{
    de::{self, Unexpected},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

use crate::{message, time::SystemTime};

use super::to_hex::ToHex;

#[derive(Clone, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
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

impl From<&message::Block> for EthBlock {
    fn from(block: &message::Block) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        EthBlock {
            number: block.view(),
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtterscanBlock {
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
pub struct OtterscanBlockWithTransactions {
    #[serde(flatten)]
    pub block: OtterscanBlock,
    pub transactions: Vec<EthTransaction>,
}

/// A block details object, returned by the Otterscan API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtterscanBlockDetails {
    block: OtterscanBlock,
    issuance: OtterscanBlockIssuance,
    #[serde(serialize_with = "hex")]
    total_fees: u64,
}

impl From<&message::Block> for OtterscanBlockDetails {
    fn from(block: &message::Block) -> Self {
        OtterscanBlockDetails {
            block: block.into(),
            issuance: OtterscanBlockIssuance {
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
pub struct OtterscanBlockIssuance {
    #[serde(serialize_with = "hex")]
    block_reward: u64,
    #[serde(serialize_with = "hex")]
    uncle_reward: u64,
    #[serde(serialize_with = "hex")]
    issuance: u64,
}

impl From<&message::Block> for OtterscanBlock {
    fn from(block: &message::Block) -> Self {
        // TODO(#79): Lots of these fields are empty/zero and shouldn't be.
        OtterscanBlock {
            number: block.view(),
            hash: H256(block.hash().0),
            parent_hash: H256(block.parent_hash().0),
            nonce: 0,
            sha_3_uncles: H256::zero(),
            transactions_root: H256::zero(),
            state_root: H256(block.state_root_hash().0),
            receipts_root: H256::zero(),
            miner: H160::zero(),
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
pub struct OtterscanBlockTransactions {
    #[serde(rename = "fullblock")]
    pub full_block: OtterscanBlockWithTransactions,
    pub receipts: Vec<EthTransactionReceipt>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtterscanTransactions {
    #[serde(rename = "txs")]
    pub transactions: Vec<EthTransaction>,
    pub receipts: Vec<EthTransactionReceiptWithTimestamp>,
    pub first_page: bool,
    pub last_page: bool,
}

/// A transaction object, returned by the Ethereum API.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransaction {
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
}

#[derive(Clone, Serialize)]
pub struct EthTransactionReceiptWithTimestamp {
    #[serde(flatten)]
    pub receipt: EthTransactionReceipt,
    #[serde(serialize_with = "hex")]
    pub timestamp: u64,
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

fn vec_hex<S: Serializer, T: ToHex>(data: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error> {
    let mut serializer = serializer.serialize_seq(Some(data.len()))?;

    data.iter()
        .try_for_each(|item| serializer.serialize_element(&item.to_hex()))?;

    serializer.end()
}

fn bool_as_int<S: Serializer>(b: &bool, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(if *b { "0x1" } else { "0x0" })
}

/// Parameters passed to `eth_call`.
#[derive(Deserialize)]
pub struct CallParams {
    #[serde(default)]
    pub from: H160,
    pub to: Option<H160>,
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

// Trace types taken from ethers.rs

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum TraceAction {
    /// transfer or call smart contract fn
    Call(TraceCall),
    /// create contract
    Create(TraceCreate),
    /// kill contract
    Suicide(TraceSuicide),
    /// mining/staking rewards? TODO: unsure
    Reward(TraceReward),
}

/// An external action type.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceActionType {
    /// Contract call.
    Call,
    /// Contract creation.
    Create,
    /// Contract suicide.
    Suicide,
    /// A block reward.
    Reward,
}

/// Call response
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct TraceCall {
    /// Sender
    pub from: H160,
    /// Recipient
    pub to: H160,
    /// Transferred Value
    pub value: U256,
    /// Gas
    pub gas: U256,
    /// Input data
    pub input: Vec<u8>,
    /// The type of the call.
    #[serde(rename = "callType")]
    pub call_type: TraceCallType,
}
/// Call type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum TraceCallType {
    /// None
    #[default]
    #[serde(rename = "none")]
    None,
    /// Call
    #[serde(rename = "call")]
    Call,
    /// Call code
    #[serde(rename = "callcode")]
    CallCode,
    /// Delegate call
    #[serde(rename = "delegatecall")]
    DelegateCall,
    /// Static call
    #[serde(rename = "staticcall")]
    StaticCall,
}
/// Create response
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct TraceCreate {
    /// Sender
    pub from: H160,
    /// Value
    pub value: U256,
    /// Gas
    pub gas: U256,
    /// Initialization code
    pub init: Vec<u8>,
}
/// Suicide
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct TraceSuicide {
    /// Address.
    pub address: H160,
    /// Refund address.
    #[serde(rename = "refundAddress")]
    pub refund_address: H160,
    /// Balance.
    pub balance: U256,
}

/// Reward action
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TraceReward {
    /// Author's address.
    pub author: H160,
    /// Reward amount.
    pub value: U256,
    /// Reward type.
    #[serde(rename = "rewardType")]
    pub reward_type: TraceRewardType,
}
/// Reward type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum TraceRewardType {
    /// Block
    #[serde(rename = "block")]
    Block,
    /// Uncle
    #[serde(rename = "uncle")]
    Uncle,
    /// EmptyStep (AuthorityRound)
    #[serde(rename = "emptyStep")]
    EmptyStep,
    /// External (attributed as part of an external protocol)
    #[serde(rename = "external")]
    External,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
/// Ad-Hoc trace API type
pub struct BlockTrace {
    /// Output Bytes
    pub output: Vec<u8>,
    /// Transaction Trace
    pub trace: Option<Vec<TransactionTrace>>,
    /// Virtual Machine Execution Trace
    #[serde(rename = "vmTrace")]
    pub vm_trace: Option<VMTrace>,
    /// State Difference
    #[serde(rename = "stateDiff")]
    pub state_diff: Option<StateDiff>,
    /// Transaction Hash
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<H256>,
}

//---------------- State Diff ----------------
/// Aux type for Diff::Changed.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct ChangedType<T> {
    /// Previous value.
    pub from: T,
    /// Current value.
    pub to: T,
}

/// Serde-friendly `StateDiff` shadow.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct StateDiff(pub BTreeMap<H160, AccountDiff>);

/// Serde-friendly `AccountDiff` shadow.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct AccountDiff {
    /// Account balance.
    pub balance: Diff<U256>,
    /// Account nonce.
    pub nonce: Diff<U256>,
    /// Account code.
    pub code: Diff<Vec<u8>>,
    /// Account storage.
    pub storage: BTreeMap<H256, Diff<H256>>,
}
/// Serde-friendly `Diff` shadow.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum Diff<T> {
    /// No change.
    #[serde(rename = "=")]
    Same,
    /// A new value has been set.
    #[serde(rename = "+")]
    Born(T),
    /// A value has been removed.
    #[serde(rename = "-")]
    Died(T),
    /// Value changed.
    #[serde(rename = "*")]
    Changed(ChangedType<T>),
}

/// Trace
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct TransactionTrace {
    /// Trace address
    #[serde(rename = "traceAddress")]
    pub trace_address: Vec<usize>,
    /// Subtraces
    pub subtraces: usize,
    /// Action
    pub action: TraceAction,
    /// Action Type
    #[serde(rename = "type")]
    pub action_type: TraceActionType,
    /// Result
    pub result: Option<TraceResponse>,
    /// Error
    pub error: Option<String>,
}

/// Response
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TraceResponse {
    /// Call
    Call(TraceCallResult),
    /// Create
    Create(TraceCreateResult),
    /// None
    #[default]
    None,
}
/// Call Result
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct TraceCallResult {
    /// Gas used
    #[serde(rename = "gasUsed")]
    pub gas_used: U256,
    /// Output bytes
    pub output: Vec<u8>,
}
/// Create Result
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct TraceCreateResult {
    /// Gas used
    #[serde(rename = "gasUsed")]
    pub gas_used: U256,
    /// Code
    pub code: Vec<u8>,
    /// Assigned address
    pub address: H160,
}

// ---------------- VmTrace ------------------------------
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[allow(clippy::upper_case_acronyms)]
/// A record of a full VM trace for a CALL/CREATE.
pub struct VMTrace {
    /// The code to be executed.
    pub code: Vec<u8>,
    /// The operations executed.
    pub ops: Vec<VMOperation>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[allow(clippy::upper_case_acronyms)]
/// A record of the execution of a single VM operation.
pub struct VMOperation {
    /// The program counter.
    pub pc: usize,
    /// The gas cost for this instruction.
    pub cost: u64,
    /// Information concerning the execution of the operation.
    pub ex: Option<VMExecutedOperation>,
    /// Subordinate trace of the CALL/CREATE if applicable.
    // #[serde(bound="VMTrace: Deserialize")]
    pub sub: Option<VMTrace>,
    /// The opcode of the executed instruction
    #[serde(rename = "op")]
    pub op: ExecutedInstruction,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[allow(clippy::upper_case_acronyms)]
/// A record of an executed VM operation.
pub struct VMExecutedOperation {
    /// The total gas used.
    #[serde(rename = "used")]
    pub used: u64,
    /// The stack item placed, if any.
    pub push: Vec<U256>,
    /// If altered, the memory delta.
    #[serde(rename = "mem")]
    pub mem: Option<MemoryDiff>,
    /// The altered storage value, if any.
    #[serde(rename = "store")]
    pub store: Option<StorageDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[allow(clippy::upper_case_acronyms)]
/// A diff of some chunk of memory.
pub struct MemoryDiff {
    /// Offset into memory the change begins.
    pub off: usize,
    /// The changed data.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[allow(clippy::upper_case_acronyms)]
/// A diff of some storage value.
pub struct StorageDiff {
    /// Which key in storage is changed.
    pub key: U256,
    /// What the value has been changed to.
    pub val: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::upper_case_acronyms)]
/// Helper to classify the executed instruction
pub enum ExecutedInstruction {
    /// The instruction is recognized
    Known(),
    /// The instruction is not recognized
    Unknown(String),
}

impl Default for ExecutedInstruction {
    fn default() -> Self {
        todo!();
        // Self::Known(Opcode::INVALID)
    }
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
