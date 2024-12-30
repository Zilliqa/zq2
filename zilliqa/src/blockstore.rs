use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use itertools::Itertools;
use libp2p::PeerId;

use crate::{
    cfg::NodeConfig,
    db::Db,
    message::{Block, ExternalMessage, InjectedProposal, Proposal, RequestBlock, ResponseBlock},
    node::MessageSender,
};

enum DownGrade {
    None,
    Partial,
    Timeout,
    Empty,
}

/// Syncing Algorithm
///
/// We rely on [crate::consensus::Consensus] informing us of newly received block proposals via:
/// * [BlockStore::process_block] for blocks that can be part of our chain, because we already have their parent.
/// * [BlockStore::buffer_proposal] for blocks that can't (yet) be part of our chain.
///
/// Both these code paths also call [BlockStore::request_missing_blocks]. This finds the greatest view of any proposal
/// we've seen (whether its part of our chain or not).

// TODO: What if we receive a fork

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
    // how many blocks to inject into the queue
    max_blocks_injected: usize,
    // our peer id
    peer_id: PeerId,
    // how many injected proposals
    injected: usize,
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
        let peer_id = message_sender.our_peer_id;

        Ok(Self {
            db,
            message_sender,
            peers,
            peer_id,
            request_timeout: config.consensus.consensus_timeout,
            max_blocks_in_flight: config.block_request_batch_size.max(31), // between 30 seconds and 3 days of blocks.
            max_blocks_injected: config.max_blocks_in_flight.min(3600), // cap to 1-hr worth of blocks
            in_flight: None,
            injected: 0,
        })
    }

    /// Match a received proposal
    pub fn mark_received_proposal(&mut self, prop: &InjectedProposal) -> Result<()> {
        if prop.from != self.peer_id {
            tracing::warn!("Received a foreign InjectedProposal from {}", prop.from);
        }
        self.injected = self.injected.saturating_sub(1);
        Ok(())
    }

    /// Process a block proposal.
    /// Checks if the parent block exists, and if not, triggers a sync.
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
            self.request_missing_blocks(Some(block))?;
            return Ok(());
        }
        Ok(())
    }

    /// Convenience function to convert a block to a proposal (add full txs)
    /// NOTE: Includes intershard transactions. Should only be used for syncing history,
    /// not for consensus messages regarding new blocks.
    fn block_to_proposal(&self, block: Block) -> Proposal {
        // since block must be valid, unwrap(s) are safe
        let txs = block
            .transactions
            .iter()
            .map(|hash| self.db.get_transaction(hash).unwrap().unwrap())
            .map(|tx| tx.verify().unwrap())
            .collect_vec();

        Proposal::from_parts(block, txs)
    }

    /// Request blocks from a hash, backwards.
    ///
    /// It will collect N blocks by following the block.parent_hash() of the requested block.
    pub fn handle_request_from_hash(
        &mut self,
        from: PeerId,
        request: RequestBlock,
    ) -> Result<ExternalMessage> {
        tracing::debug!(
            "blockstore::RequestFromHash : received a block request from {}",
            from
        );

        // TODO: Check if we should service this request
        // Validators could respond to this request if there is nothing else to do.

        let Some(omega_block) = self.db.get_block_by_hash(&request.from_hash)? else {
            // We do not have the starting block
            tracing::warn!(
                "blockstore::RequestFromHash : missing starting block {}",
                request.from_hash
            );
            let message = ExternalMessage::ResponseFromHash(ResponseBlock { proposals: vec![] });
            return Ok(message);
        };

        let batch_size = self.max_blocks_in_flight.min(request.batch_size); // mitigate DOS attacks by limiting the number of blocks we send
        let mut proposals: Vec<Proposal> = Vec::new();
        let mut hash = omega_block.parent_hash();
        while proposals.len() < batch_size {
            // grab the parent
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                // that's all we have!
                break;
            };
            hash = block.parent_hash();
            proposals.push(self.block_to_proposal(block));
        }

        let message = ExternalMessage::ResponseFromHash(ResponseBlock { proposals });
        tracing::trace!(
            ?message,
            "blockstore::RequestFromHash : responding to block request from height"
        );
        Ok(message)
    }

    /// Request for blocks from a height, forwards.
    pub fn handle_request_from_height(
        &mut self,
        from: PeerId,
        request: RequestBlock,
    ) -> Result<ExternalMessage> {
        // ...
        tracing::debug!(
            "blockstore::RequestFromHeight : received a block request from {}",
            from
        );

        // TODO: Check if we should service this request.
        // Validators shall not respond to this request.

        let Some(alpha) = self.db.get_block_by_hash(&request.from_hash)? else {
            // We do not have the starting block
            tracing::warn!(
                "blockstore::RequestFromHeight : missing starting block {}",
                request.from_hash
            );
            let message: ExternalMessage =
                ExternalMessage::ResponseFromHeight(ResponseBlock { proposals: vec![] });
            return Ok(message);
        };

        // TODO: Replace this with a single SQL query
        let batch_size = self.max_blocks_in_flight.min(request.batch_size) as u64; // mitigate DOS attacks by limiting the number of blocks we send
        let mut proposals = Vec::new();
        for num in alpha.number().saturating_add(1)..=alpha.number().saturating_add(batch_size) {
            let Some(block) = self.db.get_canonical_block_by_number(num)? else {
                // that's all we have!
                break;
            };
            proposals.push(self.block_to_proposal(block));
        }

        let message = ExternalMessage::ResponseFromHeight(ResponseBlock { proposals });
        tracing::trace!(
            ?message,
            "blockstore::RequestFromHeight : responding to block request from height"
        );
        Ok(message)
    }

    /// Pump the proposals into the chain.
    fn inject_proposals(&mut self, proposals: Vec<Proposal>) -> Result<()> {
        tracing::info!(
            "blockstore::InjectProposals : injecting {} proposals",
            proposals.len()
        );

        if proposals.is_empty() {
            return Ok(());
        }
        // Sort proposals by number
        let proposals = proposals
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        // Increment proposals injected
        self.injected = self.injected.saturating_add(proposals.len());

        // Just pump the Proposals back to ourselves.
        for p in proposals {
            tracing::trace!(
                "Injecting proposal number: {} hash: {}",
                p.number(),
                p.hash(),
            );

            self.message_sender.send_external_message(
                self.peer_id,
                ExternalMessage::InjectedProposal(InjectedProposal {
                    from: self.peer_id,
                    block: p,
                }),
            )?;
        }
        // return last proposal
        Ok(())
    }

    /// Downgrade a peer based on the response received.
    fn done_with_peer(&mut self, downgrade: DownGrade) {
        // ...
        if let Some(mut peer) = self.in_flight.take() {
            peer.score += downgrade as u32;
            self.peers.push(peer);
        }
    }

    pub fn handle_response_from_height(
        &mut self,
        from: PeerId,
        response: ResponseBlock,
    ) -> Result<()> {
        // Process whatever we have received.
        if response.proposals.is_empty() {
            // Empty response, downgrade peer
            tracing::warn!("blockstore::ResponseFromHeight : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else if response.proposals.len() < self.max_blocks_in_flight {
            // Partial response, downgrade peer
            tracing::warn!("blockstore::ResponseFromHeight : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        tracing::info!(
            "blockstore::ResponseFromHeight : received {} blocks from {}",
            response.proposals.len(),
            from
        );

        // TODO: Any additional checks we should do here?

        // Last known proposal
        let next_hash = response.proposals.last().unwrap().hash();

        // Inject received proposals
        self.inject_proposals(response.proposals)?;

        // Speculatively request more blocks, as there might be more
        if self.injected < self.max_blocks_injected {
            self.in_flight = self.get_next_peer();
            if let Some(peer) = self.in_flight.as_ref() {
                let message = ExternalMessage::RequestFromHeight(RequestBlock {
                    batch_size: self.max_blocks_in_flight,
                    from_hash: next_hash,
                });

                tracing::info!(
                    "Requesting {} future blocks from {}",
                    self.max_blocks_in_flight,
                    peer.peer_id,
                );

                self.message_sender
                    .send_external_message(peer.peer_id, message)?;
            }
        }
        Ok(())
    }

    pub fn handle_response_from_hash(
        &mut self,
        from: PeerId,
        response: ResponseBlock,
    ) -> Result<()> {
        // Check that we have enough to complete the process, otherwise ignore
        if response.proposals.is_empty() {
            // Empty response, downgrade peer, skip
            tracing::warn!("blockstore::ResponseFromHash : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else if response.proposals.len() <= self.max_blocks_in_flight / 2 {
            // Partial response, downgrade peer
            // Skip processing because we want to ensure that we have ALL the needed blocks to sync up.
            tracing::warn!("blockstore::ResponseFromHash : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
            return Ok(());
        } else {
            // only process full responses
            self.done_with_peer(DownGrade::None);
        }

        tracing::info!(
            "blockstore::ResponseFromHash : received {} blocks from {}",
            response.proposals.len(),
            from
        );

        // TODO: Any additional checks we should do here?

        // Inject the proposals
        self.inject_proposals(response.proposals)?;
        Ok(())
    }

    /// Request blocks between the current height and the given block.
    ///
    /// The approach is to request blocks in batches of `max_blocks_in_flight` blocks.
    /// If None block is provided, we request blocks from the last known canonical block forwards.
    /// If the block gap is large, we request blocks from the last known canonical block forwards.
    /// If the block gap is small, we request blocks from the latest block backwards.
    pub fn request_missing_blocks(&mut self, omega_block: Option<Block>) -> Result<()> {
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "In-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.done_with_peer(DownGrade::Timeout);
                self.in_flight = self.get_next_peer();
            } else {
                return Ok(());
            }
        } else {
            if self.injected > 0 {
                return Ok(());
            }
            self.in_flight = self.get_next_peer();
            if self.in_flight.is_none() {
                tracing::warn!("Insufficient peers available to request missing blocks");
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
        let block_gap = if let Some(omega_block) = omega_block.as_ref() {
            omega_block
                .header
                .number
                .saturating_sub(alpha_block.header.number)
        } else {
            // Trigger a RequestFromHeight if the source block is None
            self.max_blocks_in_flight as u64
        };

        // TODO: Double-check hysteresis logic - may not even be necessary to do RequestFromHash
        let message = if block_gap > self.max_blocks_in_flight as u64 / 2 {
            // we're far from latest block
            ExternalMessage::RequestFromHeight(RequestBlock {
                from_hash: alpha_block.header.hash,
                batch_size: self.max_blocks_in_flight,
            })
        } else {
            // we're close to latest block
            ExternalMessage::RequestFromHash(RequestBlock {
                from_hash: omega_block.unwrap().header.hash,
                batch_size: self.max_blocks_in_flight,
            })
        };

        let peer = self.in_flight.as_ref().unwrap();

        tracing::info!(
            "Requesting {} missing blocks from {}",
            self.max_blocks_in_flight,
            peer.peer_id,
        );

        self.message_sender
            .send_external_message(peer.peer_id, message)?;
        Ok(())
    }

    /// Add a peer to the list of peers.
    pub fn add_peer(&mut self, peer: PeerId) {
        // new peers should be tried last, which gives them time to sync first.
        let new_peer = PeerInfo {
            score: self.peers.iter().map(|p| p.score).max().unwrap_or_default(),
            peer_id: peer,
            last_used: Instant::now(),
        };
        self.peers.push(new_peer);
    }

    /// Remove a peer from the list of peers.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|p| p.peer_id != peer);
    }

    fn get_next_peer(&mut self) -> Option<PeerInfo> {
        // Minimum of 2 peers to avoid single source of truth.
        if self.peers.len() < 2 {
            return None;
        }

        let mut peer = self.peers.pop()?;
        peer.last_used = std::time::Instant::now(); // used to determine stale in-flight requests.
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
