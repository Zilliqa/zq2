//! An administrative API

use std::{collections::BTreeMap, sync::{Arc, Mutex}, time::SystemTime};

use alloy::eips::BlockId;
use anyhow::{Result, anyhow};
use jsonrpsee::{RpcModule, types::Params};
use revm::primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::types::{eth::QuorumCertificate, hex};
use crate::{api::to_hex::ToHex, cfg::EnabledApi, crypto::Hash, inspector::TouchedAddressInspector, node::Node, state::{Account, State}};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("admin_consensusInfo", consensus_info),
            ("admin_generateCheckpoint", checkpoint),
            ("admin_verifyBlocks", verify_blocks),
            ("admin_diffBetweenStates", diff_between_states),
            ("admin_diffBetweenContractStates", diff_between_contract_states),
            ("admin_unhashAccountsInTransaction", unhash_accounts_in_transaction),
            ("admin_unhashAccount", unhash_account),
            ("admin_getBlockTimestamp", get_block_timestamp),
        ]
    )
}

#[derive(Clone, Debug, Serialize)]
struct ConsensusInfo {
    #[serde(serialize_with = "hex")]
    view: u64,
    high_qc: QuorumCertificate,
    milliseconds_since_last_view_change: u64,
    milliseconds_until_next_view_change: u64,
}

fn consensus_info(_: Params, node: &Arc<Mutex<Node>>) -> Result<ConsensusInfo> {
    let node = node.lock().unwrap();

    let view = node.consensus.get_view()?;
    let high_qc = QuorumCertificate::from_qc(&node.consensus.high_qc);
    let (milliseconds_since_last_view_change, _, exponential_backoff_timeout) =
        node.consensus.get_consensus_timeout_params()?;
    let milliseconds_until_next_view_change =
        exponential_backoff_timeout.saturating_sub(milliseconds_since_last_view_change);

    Ok(ConsensusInfo {
        view,
        high_qc,
        milliseconds_since_last_view_change,
        milliseconds_until_next_view_change,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckpointResponse {
    /// File name - when this file exists, the checkpoint is done.
    file_name: String,
    /// Checkpoint hash
    hash: String,
    /// Block number as hex.
    block: String,
}

fn checkpoint(params: Params, node: &Arc<Mutex<Node>>) -> Result<CheckpointResponse> {
    let mut params = params.sequence();
    let block_id: BlockId = params.next()?;
    let mut node = node.lock().unwrap();
    let block = node
        .get_block(block_id)?
        .ok_or(anyhow!("Block {block_id} does not exist"))?;

    let (file_name, hash) = node.consensus.checkpoint_at(block.number())?;
    Ok(CheckpointResponse {
        file_name,
        hash,
        block: block.number().to_hex(),
    })
}

fn verify_blocks(params: Params, node: &Arc<Mutex<Node>>) -> Result<()> {
    let mut params = params.sequence();
    let from: BlockId = params.next()?;
    let to: BlockId = params.next()?;

    let mut node = node.lock().unwrap();

    let from = node.get_block(from)?.ok_or_else(|| anyhow!("missing block"))?.number();
    let to = node.get_block(to)?.ok_or_else(|| anyhow!("missing block"))?.number();

    let consensus = &mut node.consensus;
    let previous_state_root = consensus.state.root_hash()?;

    for block_number in from..=to {
        let block = consensus.get_canonical_block_by_number(block_number)?.ok_or_else(|| anyhow!("missing block"))?;
        let transactions = block.transactions.iter().map(|hash| Ok(consensus.get_transaction_by_hash(*hash)?.ok_or_else(|| anyhow!("missing transaction"))?.tx)).collect::<Result<_>>()?;
        let parent = consensus.get_block(&block.parent_hash())?.ok_or_else(|| anyhow!("missing block"))?;

        consensus.state.set_to_root(parent.state_root_hash().into());
        let committee = consensus.state.get_stakers(block.header)?;

        consensus.execute_block(None, &block, transactions, &committee)?;

        if consensus.state.root_hash()? != block.state_root_hash() {
            return Err(anyhow!(
                "state root hash mismatch, computed: {}, actual: {}",
                block.state_root_hash(),
                consensus.state.root_hash()?
            ));
        }
    }
    consensus.state.set_to_root(previous_state_root.into());

    Ok(())
}

fn diff_between_states(params: Params, node: &Arc<Mutex<Node>>) -> Result<BTreeMap<String, (Option<Value>, Option<Value>)>> {
    let mut params = params.sequence();
    let left = params.next()?;
    let right = params.next()?;

    let node = node.lock().unwrap();

    let left = node.consensus.state.at_root(left).accounts;
    let right = node.consensus.state.at_root(right).accounts;

    let mut left = left.iter().peekable();
    let mut right = right.iter().peekable();

    fn value(bytes: &[u8]) -> Result<Value> {
        let mut account = serde_json::to_value(bincode::deserialize::<Account>(&bytes)?)?;
        // Hacky way to re-encode EVM code bytearray as a hexadecimal string.
        if account["code"]["Evm"].is_array() {
            account["code"]["Evm"] = format!("0x{}", hex::encode(account["code"]["Evm"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect::<Vec<_>>())).into();
        }
        Ok(account)
    }

    let mut diff = BTreeMap::new();
    loop {
        // This could be much more efficient if it operated at the trie node level instead, since we could immediately
        // skip over sub-trees with common prefixes.
        match (left.peek(), right.peek()) {
            (None, None) => { break; },
            (Some((lk, lv)), Some((rk, rv))) => {
                if lk < rk {
                    let (lk, lv) = left.next().unwrap();
                    diff.insert(hex::encode(&lk), (Some(value(&lv)?), None));
                } else if rk < lk {
                    let (rk, rv) = right.next().unwrap();
                    diff.insert(hex::encode(&rk), (None, Some(value(&rv)?)));
                } else {
                    if lv != rv {
                        diff.insert(hex::encode(&lk), (Some(value(lv)?), Some(value(rv)?)));
                    }
                    left.next().unwrap();
                    right.next().unwrap();
                }
            }
            (Some(_), None) => {
                let (lk, lv) = left.next().unwrap();
                diff.insert(hex::encode(&lk), (Some(value(&lv)?), None));
            }
            (None, Some(_)) => {
                let (rk, rv) = right.next().unwrap();
                diff.insert(hex::encode(&rk), (None, Some(value(&rv)?)));
            }
        }
    }

    Ok(diff)
}


/*
            let value_from_disk = self
                .pre_state
                .get_account_trie(address)?
                .get(&storage_key(var_name, indices))?;
*/
fn diff_between_contract_states(params: Params, node: &Arc<Mutex<Node>>) -> Result<BTreeMap<String, (Option<String>, Option<String>)>> {
    let mut params = params.sequence();
    let left = params.next()?;
    let right = params.next()?;
    let address = params.next()?;

    let node = node.lock().unwrap();

    let left = node.consensus.state.at_root(left).get_account_trie(address)?;
    let right = node.consensus.state.at_root(right).get_account_trie(address)?;

    let mut left = left.iter().peekable();
    let mut right = right.iter().peekable();

    fn value(bytes: &[u8]) -> String {
        std::str::from_utf8(bytes).map(|s| s.to_owned()).unwrap_or_else(|_| hex::encode(bytes))
    }

    let mut diff = BTreeMap::new();
    loop {
        // This could be much more efficient if it operated at the trie node level instead, since we could immediately
        // skip over sub-trees with common prefixes.
        match (left.peek(), right.peek()) {
            (None, None) => { break; },
            (Some((lk, lv)), Some((rk, rv))) => {
                if lk < rk {
                    let (lk, lv) = left.next().unwrap();
                    diff.insert(value(&lk), (Some(value(&lv)), None));
                } else if rk < lk {
                    let (rk, rv) = right.next().unwrap();
                    diff.insert(value(&rk), (None, Some(value(&rv))));
                } else {
                    if lv != rv {
                        diff.insert(value(&lk), (Some(value(lv)), Some(value(rv))));
                    }
                    left.next().unwrap();
                    right.next().unwrap();
                }
            }
            (Some(_), None) => {
                let (lk, lv) = left.next().unwrap();
                diff.insert(value(&lk), (Some(value(&lv)), None));
            }
            (None, Some(_)) => {
                let (rk, rv) = right.next().unwrap();
                diff.insert(value(&rk), (None, Some(value(&rv))));
            }
        }
    }

    Ok(diff)
}

fn unhash_accounts_in_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<BTreeMap<B256, Address>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let mut inspector = TouchedAddressInspector::default();
    inspector.touched.insert(Address::ZERO);
    node.lock().unwrap().replay_transaction(txn_hash, &mut inspector)?;

    Ok(inspector.touched.into_iter().map(|address| (State::account_key(address), address)).collect())
}

fn unhash_account(params: Params, _: &Arc<Mutex<Node>>) -> Result<B256> {
    let address: Address = params.one()?;

    Ok(State::account_key(address))
}

fn get_block_timestamp(params: Params, node: &Arc<Mutex<Node>>) -> Result<SystemTime> {
    let block: BlockId = params.one()?;

    Ok(node.lock().unwrap().get_block(block)?.ok_or_else(|| anyhow!("no block"))?.timestamp())
}
