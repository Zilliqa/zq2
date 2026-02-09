use std::collections::BTreeMap;

use alloy::{
    eips::eip2930::{AccessList, AccessListItem},
    hex,
    primitives::{Address, B256, B512},
};
use anyhow::{Result, anyhow};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::Sha256;
use sha3::{
    Digest, Keccak256,
    digest::generic_array::{
        GenericArray,
        sequence::Split,
        typenum::{U12, U20},
    },
};
use zilliqa::{
    exec::{ScillaException, ScillaTransition},
    scilla::ParamValue,
    transaction::{EvmLog, ScillaLog},
};

use super::proto::{
    ProtoAccountBase, ProtoMbInfo, ProtoTransactionWithReceipt, ProtoTxBlock, proto_account_base,
    proto_mb_info, proto_transaction_core_info, proto_transaction_receipt,
    proto_tx_block::tx_block_header,
};

#[derive(Debug)]
pub struct Account {
    pub version: u32,
    pub balance: u128,
    pub nonce: u64,
    pub contract: Option<Contract>,
}

#[derive(Debug)]
pub struct Contract {
    pub code_hash: B256,
    pub state_root: B256,
}

impl Account {
    pub fn from_proto(proto: ProtoAccountBase) -> Result<Self> {
        let proto_account_base::Oneof3::Nonce(nonce) =
            proto.oneof3.ok_or_else(|| anyhow!("no nonce"))?;
        let contract = if !proto.codehash.is_empty() {
            Some(Contract {
                code_hash: B256::from_slice(&proto.codehash),
                state_root: B256::from_slice(&proto.storageroot),
            })
        } else {
            None
        };
        Ok(Account {
            version: proto.version,
            balance: u128::from_be_bytes(
                proto
                    .balance
                    .ok_or_else(|| anyhow!("no balance"))?
                    .data
                    .try_into()
                    .map_err(|v: Vec<_>| anyhow!("invalid length: {}", v.len()))?,
            ),
            nonce,
            contract,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubKey([u8; 33]);

impl PubKey {
    pub fn eth_addr(&self) -> Address {
        let verifying_key = VerifyingKey::from_sec1_bytes(&self.0).unwrap();

        // Remove the first byte before hashing - The first byte specifies the encoding tag.
        let hashed = Keccak256::digest(&verifying_key.to_encoded_point(false).as_bytes()[1..]);
        let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();

        Address::new(bytes.into())
    }

    pub fn zil_addr(&self) -> Address {
        let verifying_key = VerifyingKey::from_sec1_bytes(&self.0).unwrap();

        // Remove the first byte before hashing - The first byte specifies the encoding tag.
        let hashed = Sha256::digest(&verifying_key.to_encoded_point(false).as_bytes()[1..]);
        let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();

        Address::new(bytes.into())
    }
}

impl TryFrom<Vec<u8>> for PubKey {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        Ok(PubKey(value.try_into().map_err(|v: Vec<_>| {
            anyhow!("invalid length: {}", v.len())
        })?))
    }
}

impl From<PubKey> for Vec<u8> {
    fn from(value: PubKey) -> Self {
        value.0.into()
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct MicroBlockInfo {
    pub hash: B256,
    pub tx_root: B256,
    pub shard_id: u32,
}

impl MicroBlockInfo {
    pub fn from_proto(proto: ProtoMbInfo) -> Result<Self> {
        let proto_mb_info::Oneof3::Shardid(shard_id) =
            proto.oneof3.ok_or_else(|| anyhow!("no shardid"))?;
        Ok(MicroBlockInfo {
            hash: B256::from_slice(&proto.mbhash),
            tx_root: B256::from_slice(&proto.txroot),
            shard_id,
        })
    }
}

#[derive(Clone, Debug)]
pub struct TxBlock {
    pub version: u32,
    pub committee_hash: B256,
    pub prev_hash: B256,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub rewards: u128,
    pub block_num: u64,
    pub mb_info_hash: B256,
    pub miner_pub_key: PubKey,
    pub ds_block_num: u64,
    pub mb_infos: Vec<MicroBlockInfo>,
    pub block_hash: B256, // TODO: Remove?
    pub co_signature_1: B512,
    pub co_signature_bitmap_1: Vec<bool>,
    pub co_signature_2: B512,
    pub co_signature_bitmap_2: Vec<bool>,
    pub timestamp: u64,
    pub state_root_hash: B256,
}

impl TxBlock {
    pub fn from_proto(proto: ProtoTxBlock) -> Result<Self> {
        let header = proto.header.ok_or_else(|| anyhow!("no header"))?;
        let header_base = header
            .blockheaderbase
            .ok_or_else(|| anyhow!("no blockheaderbase"))?;
        let tx_block_header::Oneof3::Gasused(gas_used) =
            header.oneof3.ok_or_else(|| anyhow!("no gasused"))?;
        let tx_block_header::Oneof6::Blocknum(block_num) =
            header.oneof6.ok_or_else(|| anyhow!("no blocknum"))?;
        let hash_set = header.hash.ok_or_else(|| anyhow!("no hash"))?;
        let tx_block_header::Oneof10::Dsblocknum(ds_block_num) =
            header.oneof10.ok_or_else(|| anyhow!("no dsblocknum"))?;
        let block_base = proto.blockbase.ok_or_else(|| anyhow!("no blockbase"))?;
        let co_sigs = block_base.cosigs.ok_or_else(|| anyhow!("no cosigs"))?;

        // There are 2 entries containing the previous hash. Lets make sure they are consistent.
        if !header.prevhash.is_empty() {
            return Err(anyhow!(
                "inconsistent prevhash {} != {}",
                hex::encode(header_base.prevhash),
                hex::encode(header.prevhash)
            ));
        }

        Ok(TxBlock {
            version: header_base.version,
            committee_hash: B256::from_slice(&header_base.committeehash),
            prev_hash: B256::from_slice(&header_base.prevhash),
            gas_limit: header.gaslimit,
            gas_used,
            rewards: u128::from_be_bytes(
                header
                    .rewards
                    .ok_or_else(|| anyhow!("no rewards"))?
                    .data
                    .try_into()
                    .map_err(|v: Vec<_>| anyhow!("invalid length: {}", v.len()))?,
            ),
            block_num,
            mb_info_hash: B256::from_slice(&hash_set.mbinfohash),
            miner_pub_key: header
                .minerpubkey
                .ok_or_else(|| anyhow!("no minerpubkey"))?
                .data
                .try_into()?,
            ds_block_num,
            mb_infos: proto
                .mbinfos
                .into_iter()
                .map(MicroBlockInfo::from_proto)
                .collect::<Result<_>>()?,
            block_hash: B256::from_slice(&block_base.blockhash),
            co_signature_1: B512::from_slice(&co_sigs.cs1.ok_or_else(|| anyhow!("no cs1"))?.data),
            co_signature_bitmap_1: co_sigs.b1,
            co_signature_2: B512::from_slice(&co_sigs.cs2.ok_or_else(|| anyhow!("no cs2"))?.data),
            co_signature_bitmap_2: co_sigs.b2,
            timestamp: block_base.timestamp,
            state_root_hash: B256::from_slice(&hash_set.stateroothash),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub block: u64,
    pub id: B256,
    pub version: u32,
    pub to_addr: Address,
    pub sender_pub_key: PubKey,
    pub amount: u128,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub nonce: u64,
    pub code: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
    pub signature: B512,
    pub receipt: TransactionReceipt,
    pub cumulative_gas: u64,
    pub access_list: AccessList,
    pub max_priority_fee_per_gas: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
}

impl Transaction {
    pub fn from_proto(block: u64, proto: ProtoTransactionWithReceipt) -> Result<Self> {
        let transaction = proto.transaction.ok_or_else(|| anyhow!("no transaction"))?;
        let info = transaction.info.ok_or_else(|| anyhow!("no info"))?;
        let proto_transaction_core_info::Oneof2::Nonce(nonce) =
            info.oneof2.ok_or_else(|| anyhow!("no nonce"))?;
        let code = info.oneof8.map(|c| {
            let proto_transaction_core_info::Oneof8::Code(code) = c;
            code
        });
        let data = info.oneof9.map(|d| {
            let proto_transaction_core_info::Oneof9::Data(data) = d;
            data
        });
        let receipt = proto.receipt.ok_or_else(|| anyhow!("no receipt"))?;
        let proto_transaction_receipt::Oneof2::Cumgas(cumulative_gas) =
            receipt.oneof2.ok_or_else(|| anyhow!("no cumgas"))?;
        Ok(Transaction {
            block,
            id: B256::from_slice(&transaction.tranid),
            version: info.version,
            to_addr: Address::from_slice(&info.toaddr),
            sender_pub_key: info
                .senderpubkey
                .ok_or_else(|| anyhow!("no senderpubkey"))?
                .data
                .try_into()?,
            amount: u128::from_be_bytes(
                info.amount
                    .ok_or_else(|| anyhow!("no amount"))?
                    .data
                    .try_into()
                    .map_err(|v: Vec<_>| anyhow!("invalid length: {}", v.len()))?,
            ),
            gas_price: u128::from_be_bytes(
                info.gasprice
                    .ok_or_else(|| anyhow!("no gas_price"))?
                    .data
                    .try_into()
                    .map_err(|v: Vec<_>| anyhow!("invalid length: {}", v.len()))?,
            ),
            gas_limit: info.gaslimit,
            nonce,
            code,
            data,
            signature: B512::from_slice(
                &transaction
                    .signature
                    .ok_or_else(|| anyhow!("no signature"))?
                    .data,
            ),
            receipt: serde_json::from_slice(&receipt.receipt)?,
            cumulative_gas,
            access_list: info
                .access_list
                .iter()
                .map(|a| AccessListItem {
                    address: Address::from_slice(&a.address),
                    storage_keys: a.storagekeys.iter().map(|k| B256::from_slice(k)).collect(),
                })
                .collect::<Vec<_>>()
                .into(),
            max_priority_fee_per_gas: info
                .maxpriorityfeepergas
                .map(|f| {
                    Ok::<_, anyhow::Error>(u128::from_be_bytes(
                        f.data
                            .try_into()
                            .map_err(|v: Vec<_>| anyhow!("invalid length: {}", v.len()))?,
                    ))
                })
                .transpose()?,
            max_fee_per_gas: info
                .maxfeepergas
                .map(|f| {
                    Ok::<_, anyhow::Error>(u128::from_be_bytes(
                        f.data
                            .try_into()
                            .map_err(|v: Vec<_>| anyhow!("invalid length: {}", v.len()))?,
                    ))
                })
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TransactionReceipt {
    #[serde(default)]
    pub accepted: Option<bool>,
    pub success: bool,
    #[serde(deserialize_with = "str_to_int")]
    pub cumulative_gas: u64,
    #[serde(default)]
    pub event_logs: Vec<Log>,
    #[serde(default)]
    pub transitions: Vec<Transition>,
    #[serde(default)]
    pub exceptions: Vec<ScillaException>,
    #[serde(default)]
    pub errors: BTreeMap<String, Vec<u64>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Log {
    Eth(EthLog),
    Zilliqa(Value),
}

impl Log {
    pub fn to_zq2_log(&self) -> Result<zilliqa::transaction::Log> {
        match self {
            Log::Eth(l) => Ok(zilliqa::transaction::Log::Evm(EvmLog {
                address: l.address,
                topics: l.topics.clone(),
                data: l.data.clone(),
            })),
            Log::Zilliqa(log) => {
                let event_name = log
                    .get("_eventname")
                    .ok_or_else(|| anyhow!("no `_eventname` in log"))?
                    .as_str()
                    .ok_or_else(|| anyhow!("`_eventname` is not a string"))?;
                let address = log
                    .get("address")
                    .ok_or_else(|| anyhow!("no `address` in log"))?
                    .as_str()
                    .ok_or_else(|| anyhow!("`address` is not a string"))?;

                let params = log
                    .get("params")
                    .ok_or_else(|| anyhow!("no `params` in log"))?
                    .clone();
                let params: Vec<ParamValue> = serde_json::from_value(params)?;

                Ok(zilliqa::transaction::Log::Scilla(ScillaLog {
                    address: address.parse()?,
                    event_name: event_name.to_string(),
                    params,
                }))
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct EthLog {
    pub address: Address,
    pub topics: Vec<B256>,
    #[serde(deserialize_with = "hex")]
    pub data: Vec<u8>,
}

fn str_to_u128<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

fn str_to_int<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

fn hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    Ok(hex::decode(s.strip_prefix("0x").unwrap()).unwrap())
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct Transition {
    #[serde(rename = "addr")]
    address: Address,
    #[serde(default)]
    depth: u32,
    #[serde(rename = "msg")]
    message: Message,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct Message {
    #[serde(rename = "_amount", deserialize_with = "str_to_u128")]
    amount: u128,
    #[serde(rename = "_recipient")]
    recipient: Address,
    #[serde(rename = "_tag")]
    tag: String,
    #[serde(default)]
    params: Value,
}

impl From<Transition> for ScillaTransition {
    fn from(x: Transition) -> Self {
        ScillaTransition {
            from: x.address,
            to: x.message.recipient,
            depth: x.depth.into(),
            amount: zilliqa::transaction::ZilAmount::from_raw(x.message.amount),
            tag: x.message.tag,
            params: serde_json::to_string(&x.message.params).unwrap(),
        }
    }
}
