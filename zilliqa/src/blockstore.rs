use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;

use libp2p::PeerId;

use crate::{
    cfg::NodeConfig,
    db::Db,
    message::{Block, ExternalMessage, Proposal, RequestBlock},
    node::MessageSender,
};

/// Stores and manages the node's list of blocks. Also responsible for making requests for new blocks.
///
/// # Syncing Algorithm
///
/// We rely on [crate::consensus::Consensus] informing us of newly received block proposals via:
/// * [BlockStore::process_block] for blocks that can be part of our chain, because we already have their parent.
/// * [BlockStore::buffer_proposal] for blocks that can't (yet) be part of our chain.
///
/// Both these code paths also call [BlockStore::request_missing_blocks]. This finds the greatest view of any proposal
/// we've seen (whether its part of our chain or not).

#[derive(Debug)]
pub struct BlockStore {
    // database
    db: Arc<Db>,
    // message bus
    message_sender: MessageSender,
    // internal peers
    peers: BinaryHeap<PeerInfo>,
    // in-flight
    in_flight: Option<PeerInfo>,
    // in-flight timeout
    request_timeout: Duration,
    // how many blocks to request at once
    max_blocks_in_flight: usize,
}

impl BlockStore {
    pub fn new(
        config: &NodeConfig,
        db: Arc<Db>,
        message_sender: MessageSender,
        peers: Vec<PeerId>,
    ) -> Result<Self> {
        let peers = peers
            .into_iter()
            .map(|peer_id| PeerInfo {
                score: 0,
                peer_id,
                last_used: Instant::now(),
            })
            .collect();

        Ok(Self {
            db,
            message_sender,
            peers,
            in_flight: None,
            request_timeout: config.consensus.consensus_timeout,
            max_blocks_in_flight: config.max_blocks_in_flight.max(31) as usize, // between 30 seconds and 3 days of blocks.
        })
    }

    /// Route each proposal as if it were received.
    pub fn handle_response_from_height(&mut self, proposals: Vec<Proposal>) -> Result<()> {
        // Just pump the Proposals back to ourselves, and it will be picked up and processed as if it were received.
        // Only issue is the timestamp skew. We should probably fix that.
        for p in proposals {
            tracing::trace!("Received proposal from height: {:?}", p);
            self.message_sender.send_external_message(
                self.message_sender.our_peer_id,
                ExternalMessage::Proposal(p),
            )?;
        }
        Ok(())
    }

    pub fn handle_from_hash(&mut self, _: Vec<Proposal>) -> Result<()> {
        // ...
        Ok(())
    }

    pub fn process_proposal(&mut self, block: Block) -> Result<()> {
        // ...
        // check if block parent exists
        let parent_block = self.db.get_block_by_hash(&block.parent_hash())?;

        // no parent block, trigger sync
        if parent_block.is_none() {
            tracing::warn!(
                "blockstore::ProcessProposal : Parent block {} not found",
                block.parent_hash()
            );
            self.request_missing_blocks(block)?;
            return Ok(());
        }
        Ok(())
    }

    pub fn buffer_proposal(&self, _block: Block) {
        // ...
    }

    /// Request blocks between the current height and the given block.
    ///
    /// The approach is to request blocks in batches of `max_blocks_in_flight` blocks.
    /// If the block gap is large, we request blocks from the last known canonical block forwards.
    /// If the block gap is small, we request blocks from the latest block backwards.
    ///
    pub fn request_missing_blocks(&mut self, omega_block: Block) -> Result<()> {
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "In-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                let mut peer = self.in_flight.take().unwrap();
                peer.score += 1; // TODO: Downgrade score if we keep timing out.
                self.in_flight = self.get_next_peer(Some(peer));
            } else {
                return Ok(());
            }
        } else {
            self.in_flight = self.get_next_peer(None);
            if self.in_flight.is_none() {
                tracing::error!("No peers available to request missing blocks");
                return Ok(());
            }
        }

        // highest canonical block we have
        // TODO: Replace this with a single SQL query.
        let height = self
            .db
            .get_highest_canonical_block_number()?
            .unwrap_or_default();
        let alpha_block = self.db.get_canonical_block_by_number(height)?.unwrap();

        // Compute the block gap.
        let block_gap = omega_block
            .header
            .number
            .saturating_sub(alpha_block.header.number);

        // TODO: Double-check hysteresis logic.
        let message = if block_gap > self.max_blocks_in_flight as u64 / 2 {
            // we're far from latest block
            ExternalMessage::RequestFromHeight(RequestBlock {
                from_number: alpha_block.header.number,
                from_hash: alpha_block.header.hash,
                batch_size: self.max_blocks_in_flight,
            })
        } else {
            // we're close to latest block
            ExternalMessage::RequestFromHash(RequestBlock {
                from_number: omega_block.header.number,
                from_hash: omega_block.header.hash,
                batch_size: self.max_blocks_in_flight,
            })
        };

        let peer = self.in_flight.as_ref().unwrap();

        tracing::debug!(?message, "Requesting missing blocks from {}", peer.peer_id);

        self.message_sender
            .send_external_message(peer.peer_id, message)?;
        Ok(())
    }

    /// Add a peer to the list of peers.
    pub fn add_peer(&mut self, peer: PeerId) {
        // new peers should be tried last, which gives them time to sync first.
        // peers do not need to be unique.
        let new_peer = PeerInfo {
            score: self.peers.iter().map(|p| p.score).max().unwrap_or(0),
            peer_id: peer,
            last_used: Instant::now(),
        };
        self.peers.push(new_peer);
    }

    /// Remove a peer from the list of peers.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|p| p.peer_id != peer);
    }

    fn get_next_peer(&mut self, prev_peer: Option<PeerInfo>) -> Option<PeerInfo> {
        // Push the current peer into the heap, risks spamming the same peer.
        // TODO: implement a better strategy for this.
        if let Some(peer) = prev_peer {
            self.peers.push(peer);
        }

        let mut peer = self.peers.pop()?;

        // used to determine stale in-flight requests.
        peer.last_used = std::time::Instant::now();

        Some(peer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerInfo {
    score: u32,
    peer_id: PeerId,
    last_used: Instant,
}

impl Ord for PeerInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .cmp(&self.score)
            .then_with(|| other.last_used.cmp(&self.last_used))
    }
}

impl PartialOrd for PeerInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
