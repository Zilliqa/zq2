//! An administrative API

use std::{ops::RangeInclusive, sync::Arc};

use alloy::{eips::BlockId, primitives::U64};
use anyhow::{Result, anyhow};
use itertools::Itertools;
use jsonrpsee::{RpcModule, types::Params};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use super::types::{admin::VotesReceivedReturnee, eth::QuorumCertificate, hex};
use crate::{
    api::{to_hex::ToHex, types::admin::VoteCount},
    cfg::EnabledApi,
    consensus::{BlockVotes, NewViewVote, Validator},
    crypto::NodePublicKey,
    message::{BitArray, BlockHeader},
    node::Node,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
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

    let head_block = node.consensus.read().head_block();
    let mut leaders = vec![];

    while leaders.len() <= count {
        leaders.push((
            view,
            node.consensus
                .read()
                .leader_at_block(&head_block, view)
                .unwrap(),
        ));
        view += 1;
    }
    Ok(leaders)
}
