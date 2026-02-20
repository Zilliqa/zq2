//! An administrative API

use std::{collections::HashMap, ops::RangeInclusive, sync::Arc};

use alloy::{eips::BlockId, primitives::U64};
use anyhow::{Result, anyhow};
use itertools::Itertools;
use jsonrpsee::{RpcModule, types::Params};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use super::types::{admin::VotesReceivedReturnee, eth::QuorumCertificate, hex};
use crate::{
    api::{
        HandlerType, disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook,
        rpc_base_attributes, to_hex::ToHex, types::admin::VoteCount,
    },
    cfg::EnabledApi,
    checkpoint::{load_ckpt_blocks, load_ckpt_history},
    consensus::{BlockVotes, Consensus, NewViewVote, Validator},
    constants::{LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_WINDOW},
    crypto::NodePublicKey,
    message::{BitArray, BlockHeader},
    node::Node,
    precompiles::ViewHistory,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("admin_consensusInfo", consensus_info, HandlerType::Fast),
            ("admin_generateCheckpoint", checkpoint, HandlerType::Fast),
            ("admin_blockRange", admin_block_range, HandlerType::Fast),
            ("admin_forceView", force_view, HandlerType::Fast),
            ("admin_getPeers", get_peers, HandlerType::Fast),
            ("admin_votesReceived", votes_received, HandlerType::Fast),
            ("admin_clearMempool", clear_mempool, HandlerType::Fast),
            ("admin_getLeaders", get_leaders, HandlerType::Slow),
            ("admin_syncing", syncing, HandlerType::Fast),
            ("admin_missedViews", missed_views, HandlerType::Fast),
            ("admin_importViewHistory", import_history, HandlerType::Slow),
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

fn syncing(_params: Params, node: &Arc<Node>) -> Result<SyncInfo> {
    let block_range = node.consensus.read().get_block_range()?;
    let trie = node.db.state_trie()?;
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

fn missed_views(params: Params, node: &Arc<Node>) -> Result<NodeMissedViews> {
    let mut params = params.sequence();
    let current_view: u64 = params.next::<U64>()?.to::<u64>();
    let consensus = node.consensus.read();
    let (history, finalized_view) = if current_view < consensus.state().view_history.read().min_view
        && consensus.state().ckpt_view_history.is_some()
        && consensus.state().ckpt_finalized_view.is_some()
    {
        (
            consensus.state().ckpt_view_history.clone().unwrap(),
            consensus.state().ckpt_finalized_view.unwrap(),
        )
    } else {
        (
            consensus.state().view_history.clone(),
            consensus.get_finalized_view()?,
        )
    };
    let min_view = history.read().min_view;
    if min_view > 1
        && current_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW) < min_view + MISSED_VIEW_WINDOW
        || current_view > finalized_view + LAG_BEHIND_CURRENT_VIEW + 1
    {
        return Err(anyhow!("Missed view history not available"));
    }
    let missed_views = &history.read().missed_views;
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
        min_view,
        node_missed_views: missed_map,
    })
}

pub fn merge_history(
    consensus: &mut Consensus,
    imported_history: &mut ViewHistory,
    ckpt_view: u64,
) -> Result<()> {
    let finalized_view = consensus.get_finalized_view()?;
    let max_missed_view_age = consensus.config.max_missed_view_age;
    let db = consensus.db.clone();
    let history = consensus.state().view_history.clone();
    let first_existing = {
        let history_guard = history.read();
        tracing::info!(
            history = display(&*history_guard),
            "~~~~~~~~~~> initial consensus state"
        );
        history_guard.min_view
    };
    let mut last_imported = ckpt_view;

    // make sure there is no gap between the existing and the imported history
    if first_existing > last_imported {
        return Err(anyhow!(
            "Gap between imported and existing history detected"
        ));
    }
    // trim the imported missed view history
    imported_history.prune_history(finalized_view, max_missed_view_age)?;
    tracing::info!(
        history = display(&imported_history),
        "~~~~~~~~~~> trimmed imported from checkpoint"
    );
    // skip the overlapping missed views present in both histories
    loop {
        if let Some((view, _)) = imported_history.missed_views.back() {
            last_imported = *view
        } else {
            // the node's view history now starts before the remaining imported history
            return Ok(());
        }
        if last_imported < first_existing {
            break;
        }
        imported_history.missed_views.pop_back();
    }

    tracing::info!(
        history = display(&imported_history),
        "~~~~~~~~~~> non-overlapping imported from checkpoint"
    );
    let imported_missed_views = &imported_history.missed_views;
    // merge the two missed view histories and store the delta in the db
    let mut history_guard = history.write();
    imported_missed_views
        .iter()
        .rev()
        .for_each(|(view, leader)| {
            let _ = db.extend_view_history(*view, leader.as_bytes());
            history_guard.missed_views.push_front((*view, *leader));
        });
    // update min_view in consensus state and in the db
    history_guard.min_view = imported_history.min_view;
    db.set_min_view_of_view_history(history_guard.min_view)?;
    tracing::info!(
        history = display(&*history_guard),
        "~~~~~~~~~~> merged consensus state"
    );
    Ok(())
}

fn import_history(params: Params, node: &Arc<Node>) -> Result<()> {
    let mut params = params.sequence();
    let param: &str = params.next::<&str>()?;
    let path = std::path::Path::new(param);
    let (block, _, _, _) = load_ckpt_blocks(path)?;
    {
        if node
            .consensus
            .read()
            .state_at(block.number() + 1)?
            .is_none()
        {
            return Err(anyhow!("Importing missed views requires executed blocks"));
        }
    }
    let mut imported_history = load_ckpt_history(path)?;
    {
        tracing::info!(
            history = display(&imported_history),
            "~~~~~~~~~~> whole imported from checkpoint"
        );
    }
    let mut consensus = node.consensus.write();
    merge_history(&mut consensus, &mut imported_history, block.view())
}

#[derive(Clone, Debug, Serialize)]
struct ConsensusInfo {
    #[serde(serialize_with = "hex")]
    view: u64,
    high_qc: QuorumCertificate,
    milliseconds_since_last_view_change: u64,
    milliseconds_until_next_view_change: u64,
}

fn admin_block_range(_params: Params, node: &Arc<Node>) -> Result<RangeInclusive<u64>> {
    node.consensus.read().get_block_range()
}

fn consensus_info(_: Params, node: &Arc<Node>) -> Result<ConsensusInfo> {
    let view = node.consensus.read().get_view()?;
    let high_qc = QuorumCertificate::from_qc(&node.consensus.read().high_qc);
    let (milliseconds_since_last_view_change, _, exponential_backoff_timeout) =
        node.consensus.read().get_consensus_timeout_params()?;
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

fn checkpoint(params: Params, node: &Arc<Node>) -> Result<CheckpointResponse> {
    let mut params = params.sequence();
    let block_id: BlockId = params.next()?;
    let block = node
        .get_block(block_id)?
        .ok_or(anyhow!("Block {block_id} does not exist"))?;

    let (file_name, hash) = node.consensus.read().checkpoint_at(block.number())?;
    Ok(CheckpointResponse {
        file_name,
        hash,
        block: block.number().to_hex(),
    })
}

fn force_view(params: Params, node: &Arc<Node>) -> Result<bool> {
    let mut params = params.sequence();
    let view: U64 = params.next()?;
    let timeout_at: String = params.next()?;
    node.consensus
        .write()
        .force_view(view.to::<u64>(), timeout_at)?;
    Ok(true)
}

#[derive(Clone, Debug, Serialize)]
struct PeerInfo {
    pub swarm_peers: Vec<PeerId>,
    pub sync_peers: Vec<PeerId>,
}

fn get_peers(_params: Params, node: &Arc<Node>) -> Result<PeerInfo> {
    let (swarm_peers, sync_peers) = node.get_peer_ids()?;
    Ok(PeerInfo {
        swarm_peers,
        sync_peers,
    })
}

/// Returns information about votes and voters
fn votes_received(_params: Params, node: &Arc<Node>) -> Result<VotesReceivedReturnee> {
    let new_views = node
        .consensus
        .read()
        .new_views
        .iter()
        .map(|kv| (*kv.key(), kv.value().clone()))
        .collect_vec();
    let votes = node
        .consensus
        .read()
        .votes
        .iter()
        .map(|kv| (*kv.key(), kv.value().clone()))
        .collect_vec();
    let buffered_votes = node
        .consensus
        .read()
        .buffered_votes
        .clone()
        .into_iter()
        .collect_vec();

    let head_block = node.consensus.read().head_block();
    let executed_block = BlockHeader {
        number: head_block.header.number + 1,
        ..Default::default()
    };
    let committee = node
        .consensus
        .read()
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

fn clear_mempool(_params: Params, node: &Arc<Node>) -> Result<()> {
    node.consensus.read().clear_mempool();
    Ok(())
}

fn get_leaders(params: Params, node: &Arc<Node>) -> Result<Vec<(u64, Validator)>> {
    let mut params = params.sequence();
    let mut view = params.next::<U64>()?.to::<u64>();
    let count = params.next::<U64>()?.to::<usize>().min(100);
    let mut leaders = vec![];

    // find the parent block whose state must be used for the leader selection
    let parent_block = if view > node.consensus.read().get_view()? {
        node.consensus.read().head_block()
    } else {
        let lowest = node.consensus.read().get_lowest_block_view_number();
        let mut parent_view = view.saturating_sub(1);
        // there won't be too many missing views before we find a parent block due to the
        // exponential backoff unless we don't store any blocks older than the requested view
        loop {
            if parent_view < lowest {
                return Ok(leaders);
            }
            match node.consensus.read().get_block_by_view(parent_view)? {
                Some(parent_block) => break parent_block,
                None => parent_view = parent_view.saturating_sub(1),
            }
        }
    };

    let grandparent_mix_hash = node
        .consensus
        .read()
        .get_block(&parent_block.parent_hash())
        .ok()
        .flatten()
        .and_then(|block| block.header.mix_hash);

    while leaders.len() <= count {
        if let Some(leader) = node.consensus.read().leader_at_block(
            &parent_block,
            grandparent_mix_hash,
            view,
            "api_call_get_leaders",
        ) {
            leaders.push((view, leader));
        } else {
            break; // missed view history not available
        }
        view += 1;
    }
    Ok(leaders)
}
