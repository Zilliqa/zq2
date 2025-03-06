//! An administrative API

use std::{collections::BTreeMap, ops::RangeInclusive, sync::Arc};

use alloy::{eips::BlockId, primitives::U64};
use anyhow::{Result, anyhow};
use itertools::Itertools;
use jsonrpsee::{RpcModule, types::Params};
use libp2p::PeerId;
use parking_lot::RwLock;
use revm::primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::types::{admin::VotesReceivedReturnee, eth::QuorumCertificate, hex};
use crate::{
    api::{to_hex::ToHex, types::admin::VoteCount},
    cfg::EnabledApi,
    consensus::{BlockVotes, NewViewVote, Validator},
    crypto::{Hash, NodePublicKey},
    inspector::TouchedAddressInspector,
    message::{BitArray, BlockHeader},
    node::Node,
    state::{Account, State},
    time::SystemTime,
};

pub fn rpc_module(
    node: Arc<RwLock<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<RwLock<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("admin_consensusInfo", consensus_info),
            ("admin_generateCheckpoint", checkpoint),
            ("admin_blockRange", admin_block_range),
            ("admin_forceView", force_view),
            ("admin_getPeers", get_peers),
            ("admin_votesReceived", votes_received),
            ("admin_clearMempool", clear_mempool),
            ("admin_getLeaders", get_leaders),
            ("admin_verifyBlocks", verify_blocks),
            ("admin_diffBetweenStates", diff_between_states),
            (
                "admin_diffBetweenContractStates",
                diff_between_contract_states
            ),
            (
                "admin_unhashAccountsInTransaction",
                unhash_accounts_in_transaction
            ),
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

fn admin_block_range(_params: Params, node: &Arc<RwLock<Node>>) -> Result<RangeInclusive<u64>> {
    node.read().db.available_range()
}

fn consensus_info(_: Params, node: &Arc<RwLock<Node>>) -> Result<ConsensusInfo> {
    let node = node.read();

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

fn checkpoint(params: Params, node: &Arc<RwLock<Node>>) -> Result<CheckpointResponse> {
    let mut params = params.sequence();
    let block_id: BlockId = params.next()?;
    let node = node.read();
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

fn force_view(params: Params, node: &Arc<RwLock<Node>>) -> Result<bool> {
    let mut params = params.sequence();
    let view: U64 = params.next()?;
    let timeout_at: String = params.next()?;
    let mut node = node.write();
    node.consensus.force_view(view.to::<u64>(), timeout_at)?;
    Ok(true)
}

#[derive(Clone, Debug, Serialize)]
struct PeerInfo {
    pub swarm_peers: Vec<PeerId>,
    pub sync_peers: Vec<PeerId>,
}

fn get_peers(_params: Params, node: &Arc<RwLock<Node>>) -> Result<PeerInfo> {
    let node = node.read();
    let (swarm_peers, sync_peers) = node.get_peer_ids()?;
    Ok(PeerInfo {
        swarm_peers,
        sync_peers,
    })
}

/// Returns information about votes and voters
fn votes_received(_params: Params, node: &Arc<RwLock<Node>>) -> Result<VotesReceivedReturnee> {
    let node = node.read();

    let new_views = node
        .consensus
        .new_views
        .iter()
        .map(|kv| (*kv.key(), kv.value().clone()))
        .collect_vec();
    let votes = node
        .consensus
        .votes
        .iter()
        .map(|kv| (*kv.key(), kv.value().clone()))
        .collect_vec();
    let buffered_votes = node
        .consensus
        .buffered_votes
        .clone()
        .into_iter()
        .collect_vec();

    let head_block = node.consensus.head_block();
    let executed_block = BlockHeader {
        number: head_block.header.number + 1,
        ..Default::default()
    };
    let committee = node
        .consensus
        .state()
        .at_root(head_block.state_root_hash().into())
        .get_stakers(executed_block)?;

    // Helper fn to match NodePublicKey with cosigned bit array
    fn filter_voters_by_cosigned_bits(bits: &BitArray, committee: &[NodePublicKey]) -> VoteCount {
        let mut voted = vec![];
        let mut not_voted = vec![];
        for (i, peer) in committee.iter().enumerate() {
            if bits[i] {
                voted.push(*peer)
            } else {
                not_voted.push(*peer)
            }
        }
        VoteCount { voted, not_voted }
    }

    let new_view_with_voters: Vec<(u64, NewViewVote, VoteCount)> = new_views
        .iter()
        .map(|(view, new_view_vote)| {
            (
                *view,
                new_view_vote.clone(),
                filter_voters_by_cosigned_bits(&new_view_vote.cosigned, &committee),
            )
        })
        .collect();

    let votes_with_voters: Vec<(crate::crypto::Hash, BlockVotes, VoteCount)> = votes
        .iter()
        .map(|(hash, block_votes)| {
            (
                *hash,
                block_votes.clone(),
                filter_voters_by_cosigned_bits(&block_votes.cosigned, &committee),
            )
        })
        .collect();

    let returnee = VotesReceivedReturnee {
        new_views: new_view_with_voters,
        votes: votes_with_voters,
        buffered_votes,
    };

    Ok(returnee)
}

fn clear_mempool(_params: Params, node: &Arc<RwLock<Node>>) -> Result<()> {
    node.read().consensus.clear_mempool();
    Ok(())
}

fn get_leaders(params: Params, node: &Arc<RwLock<Node>>) -> Result<Vec<(u64, Validator)>> {
    let mut params = params.sequence();
    let mut view = params.next::<U64>()?.to::<u64>();
    let count = params.next::<U64>()?.to::<usize>().min(100);

    let node = node.read();
    let head_block = node.consensus.head_block();
    let mut leaders = vec![];

    while leaders.len() <= count {
        leaders.push((
            view,
            node.consensus.leader_at_block(&head_block, view).unwrap(),
        ));
        view += 1;
    }
    Ok(leaders)
}

fn verify_blocks(params: Params, node: &Arc<RwLock<Node>>) -> Result<()> {
    let mut params = params.sequence();
    let from: BlockId = params.next()?;
    let to: BlockId = params.next()?;

    let mut node = node.write();

    let from = node
        .get_block(from)?
        .ok_or_else(|| anyhow!("missing block"))?
        .number();
    let to = node
        .get_block(to)?
        .ok_or_else(|| anyhow!("missing block"))?
        .number();

    let consensus = &mut node.consensus;
    let previous_state_root = consensus.state.root_hash()?;

    for block_number in from..=to {
        let block = consensus
            .get_canonical_block_by_number(block_number)?
            .ok_or_else(|| anyhow!("missing block"))?;
        let transactions = block
            .transactions
            .iter()
            .map(|hash| {
                Ok(consensus
                    .get_transaction_by_hash(*hash)?
                    .ok_or_else(|| anyhow!("missing transaction"))?
                    .tx)
            })
            .collect::<Result<_>>()?;
        let parent = consensus
            .get_block(&block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block"))?;

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

fn diff_between_states(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<BTreeMap<String, (Option<Value>, Option<Value>)>> {
    let mut params = params.sequence();
    let left = params.next()?;
    let right = params.next()?;

    let node = node.read();

    let accounts = node.consensus.state.accounts.lock().unwrap();
    let left = accounts.at_root(left);
    let right = accounts.at_root(right);
    let mut left = left.iter().peekable();
    let mut right = right.iter().peekable();

    fn value(bytes: &[u8]) -> Result<Value> {
        let mut account = serde_json::to_value(bincode::deserialize::<Account>(&bytes)?)?;
        // Hacky way to re-encode EVM code bytearray as a hexadecimal string.
        if account["code"]["Evm"].is_array() {
            account["code"]["Evm"] = format!(
                "0x{}",
                hex::encode(
                    account["code"]["Evm"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as u8)
                        .collect::<Vec<_>>()
                )
            )
            .into();
        }
        Ok(account)
    }

    let mut diff = BTreeMap::new();
    loop {
        // This could be much more efficient if it operated at the trie node level instead, since we could immediately
        // skip over sub-trees with common prefixes.
        match (left.peek(), right.peek()) {
            (None, None) => {
                break;
            }
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

fn diff_between_contract_states(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<BTreeMap<String, (Option<String>, Option<String>)>> {
    let mut params = params.sequence();
    let left = params.next()?;
    let right = params.next()?;
    let address = params.next()?;

    let node = node.read();

    let left = node
        .consensus
        .state
        .at_root(left)
        .get_account_trie(address)?;
    let right = node
        .consensus
        .state
        .at_root(right)
        .get_account_trie(address)?;

    let mut left = left.iter().peekable();
    let mut right = right.iter().peekable();

    fn value(bytes: &[u8]) -> String {
        std::str::from_utf8(bytes)
            .map(|s| s.to_owned())
            .unwrap_or_else(|_| hex::encode(bytes))
    }

    let mut diff = BTreeMap::new();
    loop {
        // This could be much more efficient if it operated at the trie node level instead, since we could immediately
        // skip over sub-trees with common prefixes.
        match (left.peek(), right.peek()) {
            (None, None) => {
                break;
            }
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

fn unhash_accounts_in_transaction(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<BTreeMap<B256, Address>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let mut inspector = TouchedAddressInspector::default();
    inspector.touched.insert(Address::ZERO);
    node.read().replay_transaction(txn_hash, &mut inspector)?;

    Ok(inspector
        .touched
        .into_iter()
        .map(|address| (State::account_key(address), address))
        .collect())
}

fn unhash_account(params: Params, _: &Arc<RwLock<Node>>) -> Result<B256> {
    let address: Address = params.one()?;

    Ok(State::account_key(address))
}

fn get_block_timestamp(params: Params, node: &Arc<RwLock<Node>>) -> Result<SystemTime> {
    let block: BlockId = params.one()?;

    Ok(node
        .read()
        .get_block(block)?
        .ok_or_else(|| anyhow!("no block"))?
        .timestamp())
}
