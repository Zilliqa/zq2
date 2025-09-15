//! An administrative API

use std::{collections::HashMap, ops::RangeInclusive, sync::Arc};

use alloy::{eips::BlockId, primitives::U64};
use anyhow::{Result, anyhow};
use itertools::Itertools;
use jsonrpsee::{RpcModule, types::Params};
use libp2p::PeerId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::types::{admin::VotesReceivedReturnee, eth::QuorumCertificate, hex};
use crate::{
    api::{to_hex::ToHex, types::admin::VoteCount},
    cfg::EnabledApi,
    checkpoint::load_ckpt_history,
    consensus::{BlockVotes, NewViewVote, Validator},
    constants::{LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_WINDOW},
    crypto::NodePublicKey,
    message::{BitArray, BlockHeader},
    node::Node,
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
            ("admin_syncing", syncing),
            ("admin_missedViews", missed_views),
            ("admin_importViewHistory", import_history),
        ]
    )
}

#[derive(Clone, Debug, Serialize)]
struct SyncInfo {
    #[serde(serialize_with = "hex")]
    cutover_at: u64,
    #[serde(serialize_with = "hex")]
    migrate_at: u64,
    block_range: RangeInclusive<u64>,
}

fn syncing(_params: Params, node: &Arc<RwLock<Node>>) -> Result<SyncInfo> {
    let block_range = node.read().consensus.get_block_range()?;
    let trie = node.read().db.state_trie()?;
    let cutover_at = trie.get_cutover_at()?;
    let migrate_at = trie.get_migrate_at()?;
    Ok(SyncInfo {
        cutover_at,
        migrate_at,
        block_range,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeMissedViews {
    pub min_view: u64,
    pub node_missed_views: HashMap<NodePublicKey, Vec<u64>>,
}

fn missed_views(params: Params, node: &Arc<RwLock<Node>>) -> Result<NodeMissedViews> {
    let mut params = params.sequence();
    let current_view: u64 = params.next::<U64>()?.to::<u64>();
    let node = node.read();
    let history = &node.consensus.state().view_history;
    let min_view = history.min_view.lock().unwrap();
    if *min_view > 1
        && current_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW) < *min_view + MISSED_VIEW_WINDOW
        || current_view > node.consensus.get_finalized_view()? + LAG_BEHIND_CURRENT_VIEW + 1
    {
        return Err(anyhow!("Missed view history not available"));
    }
    let missed_views = history.missed_views.lock().unwrap();
    let missed_map = missed_views
        .iter()
        .filter(|&(view, _)| {
            *view >= current_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW)
                && *view < current_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW)
        })
        .fold(HashMap::new(), |mut acc, (view, leader)| {
            acc.entry(*leader)
                .and_modify(|views: &mut Vec<u64>| views.push(*view))
                .or_insert_with(|| vec![*view]);
            acc
        });
    Ok(NodeMissedViews {
        min_view: *min_view,
        node_missed_views: missed_map,
    })
}

fn import_history(params: Params, node: &Arc<RwLock<Node>>) -> Result<()> {
    let mut params = params.sequence();
    let param: &str = params.next::<&str>()?;
    let path = std::path::Path::new(param);
    let mut imported_history = load_ckpt_history(path)?;
    let node = node.read();
    let history = &node.consensus.state().view_history;
    let min_view = history.min_view.lock().unwrap();
    // make sure there is no gap between the existing and the imported history
    let mut last_imported = {
        match imported_history.missed_views.lock().unwrap().back() {
            None => 0,
            Some((view, _)) => *view,
        }
    };
    if *min_view > last_imported {
        return Err(anyhow!(
            "Gap between imported and existing history detected"
        ));
    }
    // trim the imported missed view history
    imported_history.prune_history(
        node.consensus.get_finalized_view()?,
        node.config.max_missed_view_age,
    )?;
    let first = {
        match history.missed_views.lock().unwrap().front() {
            None => 0,
            Some((view, _)) => *view,
        }
    };
    let mut imported_missed_views = imported_history.missed_views.lock().unwrap();
    // skip overlapping missed views present in both histories
    while last_imported >= first {
        imported_missed_views.pop_back();
        last_imported = imported_missed_views.back().unwrap().0;
    }
    let mut missed_views = history.missed_views.lock().unwrap();
    // merge the two missed view histories and store the delta in the db
    imported_missed_views
        .iter()
        .rev()
        .for_each(|(view, leader)| {
            node.consensus
                .db
                .extend_view_history(*view, leader.as_bytes())
                .unwrap();
            missed_views.push_front((*view, *leader));
        });
    // update min_view in consensus state and in the db
    let mut min_view = history.min_view.lock().unwrap();
    *min_view = *imported_history.min_view.lock().unwrap();
    node.consensus.db.set_min_view_of_view_history(*min_view)?;
    Ok(())
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
    node.read().consensus.get_block_range()
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
        if let Some(leader) = node.consensus.leader_at_block(&head_block, view) {
            leaders.push((view, leader));
        } else {
            break; // missed view history not available
        }
        view += 1;
    }
    Ok(leaders)
}
