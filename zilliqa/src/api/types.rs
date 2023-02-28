use k256::PublicKey;
use primitive_types::{H160, H256, H512};
use serde::{Deserialize, Serialize};

mod string {
    use std::{fmt::Display, str::FromStr};

    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

mod sec1 {
    use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use serde::{
        de::{self, Unexpected},
        Deserialize, Deserializer, Serializer,
    };

    pub fn serialize<S>(value: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&hex::encode(value.to_encoded_point(true)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = <&str>::deserialize(deserializer)?;
        let key = key
            .strip_prefix("0x")
            .unwrap_or_else(|| key.strip_prefix("0X").unwrap_or(key));
        let key = hex::decode(key)
            .map_err(|_| de::Error::invalid_value(Unexpected::Str(key), &"a hexadecimal string"))?;
        PublicKey::from_sec1_bytes(&key).map_err(|_| {
            de::Error::invalid_value(
                Unexpected::Bytes(&key),
                &"a valid SEC 1 encoded public key (compressed or uncompressed)",
            )
        })
    }
}

mod vec_sec1 {
    use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use serde::{
        de::{self, Unexpected},
        Deserialize, Deserializer, Serializer,
    };

    pub fn serialize<S>(value: &[PublicKey], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(value.iter().map(|k| hex::encode(k.to_encoded_point(true))))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PublicKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let keys = <Vec<&str>>::deserialize(deserializer)?;

        let keys = keys
            .into_iter()
            .map(|key| {
                let key = key
                    .strip_prefix("0x")
                    .unwrap_or_else(|| key.strip_prefix("0X").unwrap_or(key));
                let key = hex::decode(key).map_err(|_| {
                    de::Error::invalid_value(Unexpected::Str(key), &"a hexadecimal string")
                })?;
                PublicKey::from_sec1_bytes(&key).map_err(|_| {
                    de::Error::invalid_value(
                        Unexpected::Bytes(&key),
                        &"a valid SEC 1 encoded public key (compressed or uncompressed)",
                    )
                })
            })
            .collect::<Result<_, D::Error>>()?;

        Ok(keys)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Balance {
    #[serde(with = "string")]
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockchainInfo {
    #[serde(rename = "CurrentDSEpoch", with = "string")]
    pub current_ds_epoch: u64,
    #[serde(rename = "CurrentMiniEpoch", with = "string")]
    pub current_mini_epoch: u64,
    #[serde(rename = "DSBlockRate")]
    pub ds_block_rate: f64,
    #[serde(rename = "NumDSBlocks", with = "string")]
    pub num_ds_blocks: u64,
    #[serde(rename = "NumPeers")]
    pub num_peers: u64,
    #[serde(rename = "NumTransactions", with = "string")]
    pub num_transactions: u64,
    #[serde(rename = "NumTxBlocks", with = "string")]
    pub num_tx_blocks: u64,
    #[serde(rename = "NumTxnsDSEpoch", with = "string")]
    pub num_txns_ds_epoch: u64,
    #[serde(rename = "NumTxnsTxEpoch", with = "string")]
    pub num_txns_tx_epoch: u64,
    #[serde(
        rename = "ShardingStructure",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sharding_structure: Option<BlockchainInfoShardingStructure>,
    #[serde(rename = "TransactionRate")]
    pub transaction_rate: f64,
    #[serde(rename = "TxBlockRate")]
    pub tx_block_rate: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockchainInfoShardingStructure {
    #[serde(rename = "NumPeers")]
    pub num_peers: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DsBlock {
    pub header: DsBlockHeader,
    pub signature: H512,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DsBlockHeader {
    #[serde(rename = "BlockNum", with = "string")]
    pub block_num: u64,
    #[serde(rename = "Difficulty")]
    pub difficulty: u64,
    #[serde(rename = "DifficultyDS")]
    pub difficulty_ds: u64,
    #[serde(rename = "GasPrice", with = "string")]
    pub gas_price: u128,
    #[serde(rename = "LeaderPubKey", with = "sec1")]
    pub leader_pub_key: PublicKey,
    #[serde(rename = "PoWWinners", with = "vec_sec1")]
    pub pow_winners: Vec<PublicKey>,
    #[serde(rename = "PrevHash")]
    pub prev_hash: H256,
    #[serde(rename = "Timestamp", with = "string")]
    pub timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DsBlockListing {
    pub data: Vec<DsBlockListingDataItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DsBlockListingDataItem {
    #[serde(rename = "BlockNum")]
    pub block_num: u64,
    #[serde(rename = "Hash")]
    pub hash: H256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MinerInfo {
    #[serde(with = "vec_sec1")]
    pub dscommittee: Vec<PublicKey>,
    pub shards: Vec<MinerInfoShardsItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MinerInfoShardsItem {
    #[serde(with = "vec_sec1")]
    pub nodes: Vec<PublicKey>,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewTransaction {
    /// Transaction amount to be sent to the recipent's address. This is
    /// measured in the smallest price unit *Qa* (or 10^-12 *Zil*) in Zilliqa.
    #[serde(with = "string")]
    pub amount: u128,
    /// The smart contract source code. This is present only when deploying a
    /// new contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// `String`-ified JSON object specifying the transition parameters to be
    /// passed to a specified smart contract.
    ///
    /// - When creating a contract, this JSON object contains the *init*
    ///   parameters.
    /// - When calling a contract, this JSON object contains the *msg*
    ///   parameters.
    ///
    /// For more information on the Scilla interpreter, please visit the
    /// documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// The amount of gas units that is needed to be process this transaction.
    ///
    /// - For *regular transaction*, please use `"50"`.
    /// - For *smart contract transaction*, please consult the gas
    ///   documentation.
    #[serde(rename = "gasLimit", with = "string")]
    pub gas_limit: u64,
    /// An amount that a sender is willing to pay per unit of gas for processing
    /// this transaction. This is measured in the smallest price unit *Qa* (or
    /// 10^-12 *Zil*) in Zilliqa.
    #[serde(rename = "gasPrice", with = "string")]
    pub gas_price: u128,
    /// A transaction counter in each account. This prevents replay attacks
    /// where a transaction sending eg. 20 coins from A to B can be replayed by
    /// B over and over to continually drain A's balance.
    ///
    /// It's value should be `Current account nonce + 1`.
    pub nonce: u64,
    /// A flag for this transaction to be processed by the DS committee.
    ///
    /// This is only required for Category III transactions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<bool>,
    #[serde(rename = "pubKey", with = "sec1")]
    pub pub_key: PublicKey,
    pub signature: H512,
    /// Recipient's account address. This is represented as a `String`.
    ///
    /// NOTE:* This address has to be checksummed for every 6th bit, but the
    /// "0x" prefix is optional.
    ///
    /// For deploying new contracts, set this to
    /// `"0000000000000000000000000000000000000000"`.
    #[serde(rename = "toAddr")]
    pub to_addr: String,
    /// The decimal conversion of the bitwise concatenation of `CHAIN_ID` and
    /// `MSG_VERSION` parameters.
    ///
    /// - For mainnet, it is `65537`.
    /// - For Developer testnet, it is `21823489`.
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecentTransactions {
    #[serde(rename = "TxnHashes")]
    pub txn_hashes: Vec<H256>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction {
    #[serde(with = "string")]
    pub amount: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "gasLimit", with = "string")]
    pub gas_limit: u64,
    #[serde(rename = "gasPrice", with = "string")]
    pub gas_price: u128,
    #[serde(rename = "ID")]
    pub id: H256,
    #[serde(with = "string")]
    pub nonce: u64,
    pub receipt: TransactionReceipt,
    #[serde(rename = "senderPubKey", with = "sec1")]
    pub sender_pub_key: PublicKey,
    pub signature: H512,
    #[serde(rename = "toAddr")]
    pub to_addr: H160,
    #[serde(with = "string")]
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionInfo {
    #[serde(rename = "Info")]
    pub info: String,
    #[serde(rename = "TranID")]
    pub tran_id: H256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(with = "string")]
    pub cumulative_gas: u64,
    #[serde(with = "string")]
    pub epoch_num: u64,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub errors: std::collections::HashMap<String, Vec<u64>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exceptions: Vec<TransactionReceiptExceptionsItem>,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<TransactionReceiptTransitionsItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionReceiptExceptionsItem {
    pub line: u64,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionReceiptTransitionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<H160>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<TransactionReceiptTransitionsItemMsg>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionReceiptTransitionsItemMsg {
    #[serde(rename = "_amount", with = "string")]
    pub amount: u128,
    pub params: Vec<String>,
    #[serde(rename = "_recipient")]
    pub recipient: H160,
    #[serde(rename = "_tag")]
    pub tag: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionStatus {
    #[serde(with = "string")]
    pub amount: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "epochInserted", with = "string")]
    pub epoch_inserted: u64,
    #[serde(rename = "epochUpdated", with = "string")]
    pub epoch_updated: u64,
    #[serde(rename = "gasLimit", with = "string")]
    pub gas_limit: u64,
    #[serde(rename = "gasPrice", with = "string")]
    pub gas_price: u128,
    #[serde(rename = "ID")]
    pub id: H256,
    #[serde(rename = "_id")]
    pub object_id: TransactionStatusObjectId,
    #[serde(rename = "lastModified", with = "string")]
    pub last_modified: u64,
    #[serde(
        rename = "modificationState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub modification_state: Option<u64>,
    #[serde(with = "string")]
    pub nonce: u64,
    pub receipt: TransactionReceipt,
    #[serde(rename = "senderPubKey", with = "sec1")]
    pub sender_pub_key: PublicKey,
    pub signature: H512,
    #[serde(rename = "toAddr")]
    pub to_addr: H160,
    #[serde(with = "string")]
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionStatusObjectId {
    #[serde(rename = "$oid")]
    pub oid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxForTxBlockEx {
    #[serde(rename = "CurrPage")]
    pub curr_page: u64,
    #[serde(rename = "NumPages")]
    pub num_pages: u64,
    #[serde(rename = "Transactions")]
    pub transactions: Vec<Vec<H256>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxBodiesForTxBlockEx {
    #[serde(rename = "CurrPage")]
    pub curr_page: u64,
    #[serde(rename = "NumPages")]
    pub num_pages: u64,
    #[serde(rename = "Transactions")]
    pub transactions: Vec<Vec<Transaction>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxBlock {
    pub body: TxBlockBody,
    pub header: TxBlockHeader,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxBlockBody {
    #[serde(rename = "BlockHash")]
    pub block_hash: H256,
    #[serde(rename = "HeaderSign")]
    pub header_sign: H512,
    #[serde(rename = "MicroBlockInfos")]
    pub micro_block_infos: Vec<TxBlockBodyMicroBlockInfosItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxBlockBodyMicroBlockInfosItem {
    #[serde(rename = "MicroBlockHash")]
    pub micro_block_hash: H256,
    #[serde(rename = "MicroBlockShardId")]
    pub micro_block_shard_id: u8,
    #[serde(rename = "MicroBlockTxnRootHash")]
    pub micro_block_txn_root_hash: H256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxBlockHeader {
    #[serde(rename = "BlockNum", with = "string")]
    pub block_num: u64,
    #[serde(rename = "DSBlockNum", with = "string")]
    pub ds_block_num: u64,
    #[serde(rename = "GasLimit", with = "string")]
    pub gas_limit: u64,
    #[serde(rename = "GasUsed", with = "string")]
    pub gas_used: u64,
    #[serde(rename = "MbInfoHash")]
    pub mb_info_hash: H256,
    #[serde(rename = "MinerPubKey", with = "sec1")]
    pub miner_pub_key: PublicKey,
    #[serde(rename = "NumMicroBlocks")]
    pub num_micro_blocks: u64,
    #[serde(rename = "NumPages")]
    pub num_pages: u64,
    #[serde(rename = "NumTxns")]
    pub num_txns: u64,
    #[serde(rename = "PrevBlockHash")]
    pub prev_block_hash: H256,
    #[serde(rename = "Rewards", with = "string")]
    pub rewards: u128,
    #[serde(rename = "StateDeltaHash")]
    pub state_delta_hash: H256,
    #[serde(rename = "StateRootHash")]
    pub state_root_hash: H256,
    #[serde(rename = "Timestamp", with = "string")]
    pub timestamp: u64,
    #[serde(rename = "TxnFees", with = "string")]
    pub txn_fees: u128,
    #[serde(rename = "Version")]
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxBlockListing {
    pub data: Vec<TxBlockListingDataItem>,
    #[serde(rename = "maxPages")]
    pub max_pages: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxBlockListingDataItem {
    #[serde(rename = "BlockNum")]
    pub block_num: u64,
    #[serde(rename = "Hash")]
    pub hash: H256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateProof {
    #[serde(rename = "accountProof")]
    pub account_proof: Vec<String>,
    #[serde(rename = "stateProof")]
    pub state_proof: Vec<String>,
}
