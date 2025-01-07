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
    // peer handling an in-flight request
    in_flight: Option<PeerInfo>,
    // in-flight request timeout, before retry
    request_timeout: Duration,
    // how many blocks to request at once
    max_batch_size: usize,
    // how many blocks to inject into the queue
    max_blocks_in_flight: usize,
    // count of proposals pending in the pipeline
    in_pipeline: usize,
    // our peer id
    peer_id: PeerId,
    // internal sync state
    state: SyncState,
    // complete chain metadata, in-memory
    chain_metadata: BTreeMap<Hash, ChainMetaData>,
    // markers to segments in the chain, and the source peer for that segment.
    chain_segments: Vec<(PeerId, Hash, u64)>,
    // fixed-size queue of the most recent proposals
    recent_proposals: VecDeque<Proposal>,
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
            in_pipeline: usize::MIN,
            chain_metadata: BTreeMap::new(),
            chain_segments: Vec::new(),
            state: SyncState::Phase0,
            recent_proposals: VecDeque::with_capacity(GAP_THRESHOLD),
        })
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
        while self.recent_proposals.len() >= GAP_THRESHOLD {
            self.recent_proposals.pop_front();
        }
        self.recent_proposals.push_back(proposal);

        match self.state {
            // Check if we are out of sync
            SyncState::Phase0 if self.in_pipeline == 0 => {
                let parent_hash = self.recent_proposals.back().unwrap().header.qc.block_hash;
                if self.db.get_block_by_hash(&parent_hash)?.is_none() {
                    // No parent block, trigger sync
                    tracing::warn!("sync::SyncProposal : syncing from {parent_hash}",);
                    let block_number = self.recent_proposals.back().unwrap().number();
                    self.request_missing_metadata(Some((parent_hash, block_number)))?;
                }
            }
            // Continue phase 1, until we hit history/genesis.
            SyncState::Phase1(_, _) if self.in_pipeline < self.max_batch_size => {
                self.request_missing_metadata(None)?;
            }
            // Continue phase 2, until we have all segments.
            SyncState::Phase2(_) if self.in_pipeline < self.max_blocks_in_flight => {
                self.request_missing_blocks()?;
            }
            // Wait till 99% synced, zip it up!
            SyncState::Phase3 if self.in_pipeline == 0 => {
                let ancestor_hash = self.recent_proposals.front().unwrap().header.qc.block_hash;
                if self.db.get_block_by_hash(&ancestor_hash)?.is_some() {
                    tracing::info!(
                        "sync::SyncProposal : finishing up {} blocks for segment #0 from {ancestor_hash}",
                        self.recent_proposals.len()
                    );
                    // inject the proposals
                    let proposals = self.recent_proposals.drain(..).collect_vec();
                    self.inject_proposals(proposals)?;
                }
                self.state = SyncState::Phase0;
            }
            _ => {
                tracing::debug!(
                    "sync::SyncProposal : syncing {} blocks in pipeline",
                    self.in_pipeline
                );
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
        }
    }

    /// Retry phase 1
    ///
    /// If something went wrong, phase 1 may need to be retried for the most recent segment.
    /// Pop the segment from the landmark, and continue phase 1.
    fn retry_phase1(&mut self) -> Result<()> {
        if self.chain_segments.is_empty() {
            tracing::error!("sync::RetryPhase1 : cannot retry phase 1 without chain_segments!");
            return Ok(());
        }

        // remove the last segment from the chain metadata
        let (peer, hash, num) = self.chain_segments.pop().unwrap();
        let mut key = hash;
        while let Some(p) = self.chain_metadata.remove(&key) {
            key = p.parent_hash;
        }

        // allow retry from p1
        self.state = SyncState::Phase1(hash, num);
        tracing::info!("sync::RetryPhase1 : retrying block {hash} from {peer}");
        if DO_SPECULATIVE {
            self.request_missing_metadata(None)?;
        }
        Ok(())
    }

    /// Handle a multi-block response.
    ///
    /// This is phase 2 in the syncing algorithm, where we receive a set of blocks and inject them into the pipeline.
    /// We also remove the blocks from the chain metadata, because they are now in the pipeline.
    pub fn handle_multiblock_response(
        &mut self,
        from: PeerId,
        response: Vec<Proposal>,
    ) -> Result<()> {
        // Process only a full response
        if response.is_empty() {
            // Empty response, downgrade peer and retry phase 1.
            tracing::warn!("sync::MultiBlockResponse : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return self.retry_phase1();
        } else if response.len() < self.max_batch_size {
            // Partial response, downgrade peer but process the block.
            tracing::warn!("sync::MultiBlockResponse : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        let SyncState::Phase2(p2_hash) = self.state else {
            anyhow::bail!("sync::MultiBlockResponse : invalid state");
        };

        tracing::info!(
            "sync::MultiBlockResponse : received {} blocks for segment #{} from {}",
            response.len(),
            self.chain_segments.len(),
            from
        );

        // Spurious response
        let Some((peer_id, hash, _)) = self.chain_segments.last() else {
            anyhow::bail!("sync::MultiBlockResponse: no more chain_segments!");
        };

        // If the response is not from the expected peer, retry phase 2.
        if *peer_id != from {
            tracing::warn!("sync::MultiBlockResponse: unknown peer {from}, will retry");
            return Ok(());
        }

        // Segment history does not match, retry phase 1.
        let prop_hash = response.first().as_ref().unwrap().hash();
        if *hash != prop_hash {
            tracing::error!("sync::MultiBlockResponse : mismatched landmark {hash} != {prop_hash}");
            return self.retry_phase1();
        }

        // If the checksum does not match, retry phase 1. Maybe the node has pruned the segment.
        let checksum = response
            .iter()
            .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, p| {
                sum.with(p.hash().as_bytes())
            })
            .finalize();

        if p2_hash != checksum {
            tracing::error!("sync::MultiBlockResponse : mismatch history {checksum}");
            return self.retry_phase1();
        }

        // Response seems sane.
        let proposals = response
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        // Remove the blocks from the chain metadata
        for p in &proposals {
            if self.chain_metadata.remove(&p.hash()).is_none() {
                anyhow::bail!("missing chain data for proposal"); // this should never happen!
            }
        }

        // Done with this segment
        self.chain_segments.pop();
        self.inject_proposals(proposals)?;

        // Done with phase 2
        if self.chain_segments.is_empty() {
            self.state = SyncState::Phase3;
        } else if DO_SPECULATIVE {
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
        if !matches!(self.state, SyncState::Phase2(_)) {
            anyhow::bail!("sync::RequestMissingBlocks : invalid state");
        }
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
        } else if self.in_pipeline > self.max_blocks_in_flight {
            tracing::warn!(
                "sync::RequestMissingBlocks : syncing {} blocks in pipeline",
                self.in_pipeline
            );
            return Ok(());
        }

        // will be re-inserted below
        if let Some(peer) = self.get_next_peer() {
            // If we have no chain_segments, we have nothing to do
            if let Some((peer_id, hash, _)) = self.chain_segments.last() {
                let mut request_hashes = Vec::with_capacity(self.max_batch_size);
                let mut key = *hash; // start from this block
                while let Some(meta) = self.chain_metadata.remove(&key) {
                    request_hashes.push(meta.block_hash);
                    key = meta.parent_hash;
                    self.chain_metadata.insert(meta.block_hash, meta); // reinsert, for retries
                }

                // Checksum of the request hashes
                let checksum = request_hashes
                    .iter()
                    .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, h| {
                        sum.with(h.as_bytes())
                    })
                    .finalize();
                self.state = SyncState::Phase2(checksum);

                // Fire request, to the original peer that sent the segment metadata
                tracing::info!(
                    "sync::RequestMissingBlocks : requesting {} blocks of segment #{} from {}",
                    request_hashes.len(),
                    self.chain_segments.len(),
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
                // No more chain_segments, we're done
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
    /// construct a chain history.
    pub fn handle_metadata_response(
        &mut self,
        from: PeerId,
        response: Vec<ChainMetaData>,
    ) -> Result<()> {
        // Process whatever we have received.
        if response.is_empty() {
            // Empty response, downgrade peer and retry with a new peer.
            tracing::warn!("sync::MetadataResponse : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else if response.len() < self.max_batch_size {
            // Partial response, downgrade peer but process the response.
            tracing::warn!("sync::MetadataResponse : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        // Check the linkage of the returned chain
        let SyncState::Phase1(p1_hash, p1_num) = self.state else {
            anyhow::bail!("sync::MetadataResponse : invalid state");
        };

        let mut block_hash = p1_hash;
        let mut block_num = p1_num;
        for meta in response.iter() {
            // check that the block hash and number is as expected.
            if meta.block_hash != Hash::ZERO
                && block_hash == meta.block_hash
                && block_num == meta.block_number + 1
            {
                block_hash = meta.parent_hash;
                block_num = meta.block_number;
            } else {
                // TODO: possibly, discard and rebuild entire chain
                // if something does not match, do nothing and retry the request with the next peer.
                tracing::error!(
                    "sync::MetadataResponse : retry metadata history for {block_hash}/{block_num}"
                );
                return Ok(());
            }
            if meta.block_hash == response.last().unwrap().block_hash {
                break; // done, we do not check the last parent, because that's outside this segment
            }
        }

        // Chain segment is sane
        let segment = response;

        // Record landmark, including peer that has this set of blocks
        self.chain_segments.push((from, p1_hash, p1_num));

        // Record the oldest block in the chain's parent
        self.state = SyncState::Phase1(
            segment.last().unwrap().parent_hash,
            segment.last().unwrap().block_number,
        );

        tracing::info!(
            "sync::MetadataResponse : received {} metadata segment #{} from {}",
            segment.len(),
            self.chain_segments.len(),
            from
        );

        // Record the actual chain metadata
        let last_block_hash = segment.last().as_ref().unwrap().block_hash;
        for meta in segment {
            if self.chain_metadata.insert(meta.block_hash, meta).is_some() {
                anyhow::bail!("loop in chain!"); // there is a possible loop in the chain
            }
        }

        // If the segment does not link to our canonical history, fire the next request
        if self.db.get_block_by_hash(&last_block_hash)?.is_some() {
            // Hit our internal history. Next, phase 2.
            self.state = SyncState::Phase2(Hash::ZERO);
        } else if DO_SPECULATIVE {
            self.request_missing_metadata(None)?;
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

        // Do not respond to stale requests
        if request.request_at.elapsed()? > self.request_timeout {
            tracing::warn!("sync::MetadataRequest : stale request");
            return Ok(ExternalMessage::Acknowledgement);
        }

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
    pub fn request_missing_metadata(&mut self, block: Option<(Hash, u64)>) -> Result<()> {
        if matches!(self.state, SyncState::Phase2(_)) || matches!(self.state, SyncState::Phase3) {
            anyhow::bail!("sync::RequestMissingMetadata : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "sync::RequestMissingMetadata : in-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.done_with_peer(DownGrade::Timeout);
            } else {
                return Ok(());
            }
        } else if self.in_pipeline > self.max_batch_size {
            // anything more than this and we cannot check whether the segment hits history
            tracing::warn!(
                "sync::RequestMissingMetadata :  syncing {} blocks in pipeline",
                self.in_pipeline
            );
            return Ok(());
        }

        if let Some(peer) = self.get_next_peer() {
            let message = match self.state {
                SyncState::Phase1(hash, _) => ExternalMessage::MetaDataRequest(RequestBlock {
                    request_at: SystemTime::now(),
                    from_hash: hash,
                    batch_size: self.max_batch_size,
                }),
                SyncState::Phase0 if block.is_some() => {
                    let (hash, number) = block.unwrap();
                    self.state = SyncState::Phase1(hash, number);
                    ExternalMessage::MetaDataRequest(RequestBlock {
                        request_at: SystemTime::now(),
                        from_hash: hash,
                        batch_size: self.max_batch_size,
                    })
                }
                _ => anyhow::bail!("sync::MissingMetadata : invalid state"),
            };

            tracing::info!(
                ?message,
                "sync::RequestMissingMetadata : requesting missing chain from {}",
                peer.peer_id
            );
            self.message_sender
                .send_external_message(peer.peer_id, message)?;

            self.in_flight = Some(peer);
        } else {
            tracing::warn!(
                "sync::RequestMissingMetadata : insufficient peers to request missing blocks"
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
        self.in_pipeline = self.in_pipeline.saturating_add(proposals.len());
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
            self.in_pipeline
        );
        // return last proposal
        Ok(())
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
        self.in_pipeline = self.in_pipeline.saturating_sub(1);
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

/// Peer downgrade states/values, for downgrading an internal peer from selection.
#[derive(Debug)]
enum DownGrade {
    None,
    Partial,
    Timeout,
    Empty,
}

/// Sync state
#[derive(Debug)]
enum SyncState {
    Phase0,
    Phase1(Hash, u64),
    Phase2(Hash),
    Phase3,
}
