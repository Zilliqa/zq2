use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use itertools::Itertools;
use libp2p::PeerId;

use crate::{
    cfg::NodeConfig,
    crypto::Hash,
    db::Db,
    message::{Block, ChainMetaData, ExternalMessage, InjectedProposal, Proposal, RequestBlock},
    node::MessageSender,
    time::SystemTime,
};

enum DownGrade {
    None,
    Partial,
    Timeout,
    Empty,
}

// Syncing Algorithm
//
// When a Proposal is received by Consensus, we check if the parent exists in our DB.
// If not, then it triggers a syncing algorithm.
//
// PHASE 1: Request missing chain metadata.
// The entire chain metadata is stored in-memory, and is used to construct a chain of metadata.
// 1. We start with the latest Proposal and request the chain of metadata from a peer.
// 2. We construct the chain of metadata, based on the response received.
// 3. If the last block does not exist in our canonical history, we request for additional metadata.
// 4. If the last block exists, we have hit our canonical history.
// 5. Move to Phase 2.
//
// PHASE 2: Request missing blocks.
// Once the chain metadata is constructed, we request the missing blocks to replay the history.
// 1. We construct a set of hashes, from the in-memory chain metadata.
// 2. We send these block hashes to the same Peer (that sent the metadata) for retrieval.
// 3. We inject the Proposals into the pipeline, when the response is received.
// 4. If there are still missing blocks, we ask for more, from 1.
// 5. If there are no more missing blocks, we have filled up all blocks from the chain metadata.
// 6. Ready for Phase 3.
//
// PHASE 3: Zip it up.
// Phase 1&2 may run several times that brings up 99% of the chain. This closes the final gap.
// 1. We queue all newly received Proposals, while Phase 1 & 2 were in progress.
// 2. We check the head of the queue if its parent exists in our canonical history.
// 3. If it does not, we trigger Phase 1&2.
// 4. If it does, we inject the entire queue into the pipeline.
// 5. We are caught up.

const GAP_THRESHOLD: usize = 20; // Size of internal Proposal cache.
const DO_SPECULATIVE: bool = false; // Speeds up syncing by speculatively fetching blocks.

#[derive(Debug)]
pub struct Sync {
    // database
    db: Arc<Db>,
    // message bus
    message_sender: MessageSender,
    // internal list of peers, maintained with add_peer/remove_peer.
    peers: BinaryHeap<PeerInfo>,
    // in-flight
    in_flight: Option<PeerInfo>,
    // in-flight timeout
    request_timeout: Duration,
    // how many blocks to request at once
    max_batch_size: usize,
    // how many blocks to inject into the queue
    max_blocks_in_flight: usize,
    // our peer id
    peer_id: PeerId,
    // how many injected proposals
    injected: usize,
    // complete chain metadata
    chain_metadata: BTreeMap<Hash, ChainMetaData>,
    // phase 1 cursor
    p1_metadata: Option<ChainMetaData>,
    // phase 2 cursor
    p2_metadata: Option<Hash>,
    // stack of chain landmarks
    landmarks: Vec<(Hash, PeerId)>,
    // fixed-size queue of latest proposals
    zip_queue: VecDeque<Proposal>,
}

impl Sync {
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
            max_batch_size: config.block_request_batch_size.max(31), // between 30 seconds and 3 days of blocks.
            max_blocks_in_flight: config.max_blocks_in_flight.min(3600), // cap to 1-hr worth of blocks
            in_flight: None,
            injected: 0,
            chain_metadata: BTreeMap::new(),
            p1_metadata: None,
            landmarks: Vec::new(),
            p2_metadata: None,
            zip_queue: VecDeque::with_capacity(GAP_THRESHOLD),
        })
    }

    /// Mark a received proposal
    ///
    /// Mark a proposal as received, and remove it from the cache.
    pub fn mark_received_proposal(&mut self, prop: &InjectedProposal) -> Result<()> {
        if prop.from != self.peer_id {
            tracing::error!(
                "sync::MarkReceivedProposal : foreign InjectedProposal from {}",
                prop.from
            );
        }
        if let Some(p) = self.chain_metadata.remove(&prop.block.hash()) {
            tracing::warn!(
                "sync::MarkReceivedProposal : removing stale metadata {}",
                p.block_hash
            );
        }
        self.injected = self.injected.saturating_sub(1);
        Ok(())
    }

    /// Sync a block proposal.
    ///
    /// This is the main entry point for syncing a block proposal.
    /// We start by enqueuing all proposals, and then check if the parent block exists in history.
    /// If the parent block exists, we do nothing. Ttherwise, we check the oldest one in the queue.
    /// If we find its parent in history, we inject the entire queue.
    ///
    /// We do not perform checks on the Proposal here. This is done in the consensus layer.
    pub fn sync_proposal(&mut self, proposal: Proposal) -> Result<()> {
        // just stuff the latest proposal into the fixed-size queue.
        while self.zip_queue.len() >= GAP_THRESHOLD {
            self.zip_queue.pop_front();
        }
        self.zip_queue.push_back(proposal);

        // TODO: Replace with single SQL query
        // Check if block parent exist in history
        let parent_hash = self.zip_queue.back().unwrap().header.qc.block_hash;
        if self.db.get_block_by_hash(&parent_hash)?.is_none() {
            // Check if oldes block exists in the history. If it does, we have synced up 99% of the chain.
            let ancestor_hash = self.zip_queue.front().unwrap().header.qc.block_hash;
            if self.zip_queue.len() == 1 || self.db.get_block_by_hash(&ancestor_hash)?.is_none() {
                // No ancestor block, trigger sync
                tracing::warn!(
                    "sync::SyncProposal : parent block {} not found",
                    parent_hash
                );
                if self.p2_metadata.is_some() {
                    // Continue phase 2
                    self.request_missing_blocks()?;
                } else if self.p1_metadata.is_some() {
                    // Continue phase 1
                    self.request_missing_chain(None)?;
                } else {
                    // Start phase 1
                    let block_number = self.zip_queue.back().unwrap().number();
                    self.request_missing_chain(Some((parent_hash, block_number)))?;
                }
            } else {
                // 99% synced, zip it up!
                tracing::info!(
                    "sync::SyncProposal : zip up {} blocks from {}",
                    self.zip_queue.len(),
                    ancestor_hash
                );
                // parent block exists, inject the proposal
                let proposals = self.zip_queue.drain(..).collect_vec();
                self.inject_proposals(proposals)?;
                // we're done
            }
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

    /// Convenience function to extract metadata from the block.
    fn block_to_metadata(&self, block: Block) -> ChainMetaData {
        ChainMetaData {
            block_number: block.number(),
            block_hash: block.hash(),
            parent_hash: block.parent_hash(),
            block_timestamp: block.timestamp(),
        }
    }

    /// Handle a multi-block response.
    ///
    /// This is the final step in the syncing algorithm, where we receive a set of blocks and inject them into
    /// the pipeline. We also remove the blocks from the chain metadata, because they are now in the pipeline.
    pub fn handle_multiblock_response(
        &mut self,
        from: PeerId,
        response: Vec<Proposal>,
    ) -> Result<()> {
        // Process whatever we received
        if response.is_empty() {
            // Empty response, downgrade peer
            tracing::warn!("sync::MultiBlockResponse : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
        } else if response.len() < self.max_batch_size {
            // Partial response, downgrade peer
            tracing::warn!("sync::MultiBlockResponse : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        tracing::info!(
            "sync::MultiBlockResponse : received {} blocks for segment #{} from {}",
            response.len(),
            self.landmarks.len(),
            from
        );

        let Some((hash, peer_id)) = self.landmarks.last() else {
            tracing::error!("sync::MultiBlockResponse: no more landmarks!");
            return Ok(());
        };

        // Check that this segment is from the requested peer.
        if *peer_id != from {
            tracing::error!("sync::MultiBlockResponse: response received from unknown peer {from}");
            return Ok(());
        }

        // Check that this segment starts at the expected landmark
        let prop_hash = response.first().as_ref().unwrap().hash();
        if *hash != prop_hash {
            tracing::warn!(
                "sync::MultiBlockResponse : mismatched landmark {} != {}",
                hash,
                prop_hash,
            );
            return Ok(());
        }

        // Check it matches request hashes
        let checksum = response
            .iter()
            .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, p| {
                sum.with(p.hash().as_bytes())
            })
            .finalize();
        if self.p2_metadata.unwrap_or_else(|| Hash::ZERO) != checksum {
            tracing::error!("sync::MultiBlockResponse : mismatch request checksum {checksum}");
            return Ok(());
        }

        // Sort proposals by number, ascending
        let proposals = response
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        // Remove the blocks from the chain metadata, if they exist
        for p in &proposals {
            self.chain_metadata.remove(&p.hash());
        }

        self.landmarks.pop();
        self.inject_proposals(proposals)?;

        // Done with phase 2, allow phase 1 to restart.
        if self.landmarks.is_empty() {
            self.p1_metadata = None;
            self.chain_metadata.clear();
        } else if DO_SPECULATIVE && self.injected < self.max_blocks_in_flight {
            // Speculatively request more blocks
            self.request_missing_blocks()?;
        }

        Ok(())
    }

    /// Returns a list of Proposals
    ///
    /// Given a set of block hashes, retrieve the list of proposals from its history.
    /// Returns this list of proposals to the requestor.
    pub fn handle_multiblock_request(
        &mut self,
        from: PeerId,
        request: Vec<Hash>,
    ) -> Result<ExternalMessage> {
        tracing::debug!(
            "sync::MultiBlockRequest : received a {} multiblock request from {}",
            request.len(),
            from
        );

        // TODO: Any additional checks
        // Validators should not respond to this, unless they are free e.g. stuck in an exponential backoff.

        let batch_size: usize = self.max_batch_size.min(request.len()); // mitigate DOS by limiting the number of blocks we return
        let mut proposals = Vec::with_capacity(batch_size);
        for hash in request {
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            proposals.push(self.block_to_proposal(block));
        }

        let message = ExternalMessage::MultiBlockResponse(proposals);
        Ok(message)
    }

    /// Request missing blocks from the chain.
    ///
    /// It constructs a set of hashes, which constitute the series of blocks that are missing.
    /// These hashes are then sent to a Peer for retrieval.
    /// This is Part 2 of the syncing algorithm.
    fn request_missing_blocks(&mut self) -> Result<()> {
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "sync::RequestMissingBlocks : in-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.done_with_peer(DownGrade::Timeout);
            } else {
                return Ok(());
            }
        } else if self.injected > self.max_blocks_in_flight {
            return Ok(());
        } else if self.p2_metadata.is_none() {
            tracing::warn!("sync::RequestMissingBlocks : no metadata to request missing blocks");
            return Ok(());
        }

        // will be re-inserted below
        if let Some(peer) = self.get_next_peer() {
            self.p2_metadata = None;
            // If we have no landmarks, we have nothing to do
            if let Some((hash, peer_id)) = self.landmarks.last() {
                let mut hash = *hash; // peek at the last value
                let mut request_hashes = Vec::with_capacity(self.max_batch_size);
                while let Some(meta) = self.chain_metadata.remove(&hash) {
                    request_hashes.push(meta.block_hash);
                    hash = meta.parent_hash;
                    // TODO: Implement retry mechanism
                    // self.chain_metadata.insert(hash, meta); // reinsert, for retries
                }

                // Checksum of the request hashes
                let checksum = request_hashes
                    .iter()
                    .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, h| {
                        sum.with(h.as_bytes())
                    })
                    .finalize();
                self.p2_metadata = Some(checksum);

                // Fire request, to the original peer that sent the segment metadata
                tracing::info!(
                    "sync::RequestMissingBlocks : requesting {} blocks of segment #{} from {}",
                    request_hashes.len(),
                    self.landmarks.len(),
                    peer_id,
                );
                self.message_sender.send_external_message(
                    *peer_id,
                    ExternalMessage::MultiBlockRequest(request_hashes),
                )?;
                self.peers.push(peer); // reinsert peer, as we will be using a faux peer below
                self.in_flight = Some(PeerInfo {
                    peer_id: *peer_id,
                    last_used: std::time::Instant::now(),
                    score: u32::MAX, // used to indicate faux peer, will not be added to the group of peers
                });
            } else {
                // No more landmarks, we're done
                self.peers.push(peer);
            }
        } else {
            tracing::warn!(
                "sync::RequestMissingBlocks : insufficient peers to request missing blocks"
            );
        }
        Ok(())
    }

    /// Handle a response to a metadata request.
    ///
    /// This is the first step in the syncing algorithm, where we receive a set of metadata and use it to
    /// construct a chain history. We then request the missing blocks from the chain.
    pub fn handle_metadata_response(
        &mut self,
        from: PeerId,
        response: Vec<ChainMetaData>,
    ) -> Result<()> {
        // Process whatever we have received.
        if response.is_empty() {
            // Empty response, downgrade peer
            tracing::warn!("sync::MetadataResponse : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else if response.len() < self.max_batch_size {
            // Partial response, downgrade peer
            tracing::warn!("sync::MetadataResponse : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        // Check the linkage of the returned chain
        let Some(p1) = self.p1_metadata.as_ref() else {
            tracing::error!(
                "no way to check chain linkage from {}",
                response.first().unwrap().block_hash
            );
            return Ok(());
        };
        let mut parent_hash = p1.parent_hash;
        let mut parent_num = p1.block_number;
        for meta in response.iter() {
            // check that the block hash and number is as expected.
            if meta.block_hash != Hash::ZERO
                && meta.block_hash == parent_hash
                && parent_num == meta.block_number + 1
            {
                parent_hash = meta.parent_hash;
                parent_num = meta.block_number;
            } else {
                // if something does not match, we will retry the request with the next peer.
                // TODO: possibly, discard and rebuild entire chain
                tracing::error!(
                    "sync::MetadataResponse : retry metadata history for {}",
                    parent_hash
                );
                return Ok(());
            }
            if meta.block_hash == response.last().unwrap().block_hash {
                break; // done, we do not check the last parent, because that's outside this segment
            }
        }

        // Chain segment is sane
        let segment = response;

        // Record the oldest block in the chain
        self.p1_metadata = Some(segment.last().unwrap().clone());

        // TODO: Insert intermediate landmarks
        // Record landmark, including peer that has this set of blocks
        self.landmarks
            .push((segment.first().as_ref().unwrap().block_hash, from));

        tracing::info!(
            "sync::MetadataResponse : received {} metadata segment #{} from {}",
            segment.len(),
            self.landmarks.len(),
            from
        );

        // Record the actual chain metadata
        for meta in segment {
            if self.chain_metadata.insert(meta.block_hash, meta).is_some() {
                anyhow::bail!("loop in chain!"); // there is a possible loop in the chain
            }
        }

        // If the segment does not link to our canonical history, fire the next request
        if self
            .db
            .get_block_by_hash(&self.p1_metadata.as_ref().unwrap().block_hash)?
            .is_some()
        {
            // Hit our internal history. Start phase 2.
            self.p2_metadata = Some(self.p1_metadata.as_ref().unwrap().block_hash);
        } else if DO_SPECULATIVE {
            self.request_missing_chain(None)?;
        }

        Ok(())
    }

    /// Returns the metadata of the chain from a given hash.
    ///
    /// This constructs a historical chain going backwards from a hash, by following the parent_hash.
    /// It collects N blocks and returns the metadata of that particular chain.
    /// This is mainly used in Phase 1 of the syncing algorithm, to construct a chain history.
    pub fn handle_metadata_request(
        &mut self,
        from: PeerId,
        request: RequestBlock,
    ) -> Result<ExternalMessage> {
        tracing::debug!(
            "sync::MetadataRequest : received a metadata request from {}",
            from
        );

        // TODO: Check if we should service this request
        // Validators could respond to this request if there is nothing else to do.

        let batch_size: usize = self.max_batch_size.min(request.batch_size); // mitigate DOS by limiting the number of blocks we return
        let mut metas = Vec::with_capacity(batch_size);
        let mut hash = request.from_hash;
        while metas.len() < batch_size {
            // grab the parent
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            hash = block.parent_hash();
            metas.push(self.block_to_metadata(block));
        }

        let message = ExternalMessage::MetaDataResponse(metas);
        tracing::trace!(
            ?message,
            "sync::MetadataFromHash : responding to block request"
        );
        Ok(message)
    }

    /// Request missing chain from a peer.
    ///
    /// This constructs a chain history by requesting blocks from a peer, going backwards from a given block.
    /// If phase 1 is in progress, it continues requesting blocks from the last known phase 1 block.
    /// Otherwise, it requests blocks from the given omega_block.
    pub fn request_missing_chain(&mut self, block: Option<(Hash, u64)>) -> Result<()> {
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "sync::RequestMissingChain : in-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.done_with_peer(DownGrade::Timeout);
            } else {
                return Ok(());
            }
        } else if self.injected > 0 {
            tracing::warn!(
                "sync::RequestMissingChain : too many {} blocks in flight",
                self.injected
            );
            return Ok(());
        }

        if let Some(peer) = self.get_next_peer() {
            let message = if let Some(meta) = self.p1_metadata.as_ref() {
                ExternalMessage::MetaDataRequest(RequestBlock {
                    from_number: 0,
                    from_hash: meta.parent_hash,
                    batch_size: self.max_batch_size,
                })
            } else if let Some((hash, number)) = block {
                // insert the starting point for phase 1
                self.p1_metadata = Some(ChainMetaData {
                    block_hash: Hash::ZERO, // invalid block hash
                    block_number: number,
                    parent_hash: hash,
                    block_timestamp: SystemTime::UNIX_EPOCH,
                });
                ExternalMessage::MetaDataRequest(RequestBlock {
                    from_number: 0,
                    from_hash: hash,
                    batch_size: self.max_batch_size,
                })
            } else {
                todo!("sync::RequestMissingChain : no metadata to request missing blocks");
            };

            tracing::info!(
                ?message,
                "sync::RequestMissingChain : requesting missing chain from {}",
                peer.peer_id
            );
            self.message_sender
                .send_external_message(peer.peer_id, message)?;

            self.in_flight = Some(peer);
        } else {
            tracing::warn!(
                "sync::RequestMissingChain : insufficient peers to request missing blocks"
            );
        }
        Ok(())
    }

    /// Inject the proposals into the chain.
    ///
    /// Besides pumping the set of Proposals into the processing pipeline, it also records the
    /// last known Proposal in the pipeline. This is used for speculative fetches, and also for
    /// knowing where to continue fetching from.
    fn inject_proposals(&mut self, proposals: Vec<Proposal>) -> Result<()> {
        if proposals.is_empty() {
            return Ok(());
        }

        // Increment proposals injected
        self.injected = self.injected.saturating_add(proposals.len());
        let len = proposals.len();

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

        tracing::debug!(
            "sync::InjectProposals : injected {}/{} proposals",
            len,
            self.injected
        );
        // return last proposal
        Ok(())
    }

    /// Downgrade a peer based on the response received.
    fn done_with_peer(&mut self, downgrade: DownGrade) {
        if let Some(mut peer) = self.in_flight.take() {
            // Downgrade peer, if necessary
            peer.score = peer.score.saturating_add(downgrade as u32);
            // Ensure that the next peer is equal or better, to avoid a single source of truth.
            peer.score = peer.score.max(self.peers.peek().unwrap().score);
            // Reinsert peers that are good
            if peer.score < u32::MAX {
                self.peers.push(peer);
            }
        }
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
