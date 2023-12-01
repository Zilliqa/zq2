use primitive_types::{H256, H512};
use serde::Serialize;

use crate::{message::Block, time::SystemTime};

use super::hex;

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
