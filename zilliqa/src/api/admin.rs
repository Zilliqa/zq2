//! An administrative API

use std::{ops::RangeInclusive, sync::Arc};

use alloy::{eips::BlockId, primitives::U64};
use anyhow::{Result, anyhow};
use itertools::Itertools;
use jsonrpsee::{RpcModule, types::Params};
use libp2p::PeerId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::types::{admin::VotesReceivedReturnee, eth::QuorumCertificate, hex};
use crate::{api::to_hex::ToHex, cfg::EnabledApi, node::Node};

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

/// Returns information about votes
fn votes_received(_params: Params, node: &Arc<RwLock<Node>>) -> Result<VotesReceivedReturnee> {
    let node = node.read();

    let new_views = node.consensus.new_views.clone().into_iter().collect_vec();
    let votes = node.consensus.votes.clone().into_iter().collect_vec();
    let buffered_votes = node
        .consensus
        .buffered_votes
        .clone()
        .into_iter()
        .collect_vec();
    let returnee = VotesReceivedReturnee {
        new_views,
        votes,
        buffered_votes,
    };
    Ok(returnee)
}

fn clear_mempool(_params: Params, node: &Arc<RwLock<Node>>) -> Result<()> {
    let mut node = node.write();

    node.consensus.clear_mempool();
    Ok(())
}
