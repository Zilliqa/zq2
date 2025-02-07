use std::{
    cmp::Ordering,
    collections::{BinaryHeap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use itertools::Itertools;
use libp2p::PeerId;
use rusqlite::types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

use crate::{
    api::types::eth::{SyncingMeta, SyncingStruct},
    cfg::NodeConfig,
    crypto::Hash,
    db::Db,
    message::{
        Block, BlockHeader, BlockRequest, BlockResponse, ExternalMessage, InjectedProposal,
        Proposal, QuorumCertificate, RequestBlocksByHeight,
    },
    node::{MessageSender, OutgoingMessageFailure, RequestId},
    time::SystemTime,
};

// Syncing Algorithm
//
// When a Proposal is received by Consensus, we check if the parent exists in our DB.
// If not, then it triggers a syncing algorithm.
//
// PHASE 1: Request missing chain metadata.
// The entire chain metadata is stored in-memory, and is used to construct a chain of metadata.
// Each metadata basically contains the block_hash, block_number, parent_hash, and view_number.
// 1. We start with the latest Proposal and request the chain of metadata from a peer.
// 2. We construct the chain of metadata, based on the response received.
// 3. If the last block does not exist in our history, we request for additional metadata.
// 4. If the last block exists, we have hit our history, we move to Phase 2.
//
// PHASE 2: Request missing blocks.
// Once the chain metadata is constructed, we fill in the missing blocks to replay the history.
// We do not make any judgements (other than sanity) on the block and leave that up to consensus.
// 1. We construct a set of hashes, from the in-memory chain metadata.
// 2. We request these blocks from the same Peer that sent the metadata.
// 3. We inject the received Proposals into the pipeline.
// 4. If there are still missing blocks, we ask for more.
// 5. If there are no more missing blocks, we move to Phase 3.
//
// PHASE 3: Zip it up.
// Phase 1&2 may run several times and bring up 99% of the chain, but it will never catch up.
// This closes the final gap.
// 1. We queue all recently received Proposals, while Phase 1 & 2 were in progress.
// 2. We check the head of the queue, if its parent exists in our history.
// 3. If it does not, our history is too far away, we run Phase 1 again.
// 4. If it does, we inject the entire queue into the pipeline.
// 5. We are fully synced.

#[derive(Debug)]
pub struct Sync {
    // database
    db: Arc<Db>,
    // message bus
    message_sender: MessageSender,
    // internal peers
    peers: Arc<SyncPeers>,
    // peer handling an in-flight request
    in_flight: Option<(PeerInfo, RequestId)>,
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
    // fixed-size queue of the most recent proposals
    recent_proposals: VecDeque<Proposal>,
    // for statistics only
    inject_at: Option<(std::time::Instant, usize)>,
    // record data for eth_syncing() RPC call.
    started_at_block_number: u64,
    highest_block_seen: u64,
    retry_count: u64,
    timeout_count: u64,
    empty_count: u64,
    headers_downloaded: u64,
    blocks_downloaded: u64,
    // checkpoint, if set
    checkpoint_hash: Hash,
}

impl Sync {
    // Speed up syncing by speculatively fetching blocks in Phase 1 & 2.
    #[cfg(not(debug_assertions))]
    const DO_SPECULATIVE: bool = true;
    #[cfg(debug_assertions)]
    const DO_SPECULATIVE: bool = false;

    pub fn new(
        config: &NodeConfig,
        db: Arc<Db>,
        latest_block: &Option<Block>,
        message_sender: MessageSender,
        peers: Arc<SyncPeers>,
    ) -> Result<Self> {
        let peer_id = message_sender.our_peer_id;
        let max_batch_size = config.block_request_batch_size.clamp(10, 100);
        let max_blocks_in_flight = config.max_blocks_in_flight.clamp(max_batch_size, 1000);

        // Start from reset, or continue sync
        let state = if db.count_sync_segments()? == 0 {
            SyncState::Phase0
        } else {
            SyncState::Retry1 // continue sync
        };

        let (latest_block_number, latest_block_hash) = latest_block
            .as_ref()
            .map_or_else(|| (u64::MIN, Hash::ZERO), |b| (b.number(), b.hash()));

        Ok(Self {
            db,
            message_sender,
            peer_id,
            peers,
            max_batch_size,
            max_blocks_in_flight,
            in_flight: None,
            in_pipeline: usize::MIN,
            state,
            recent_proposals: VecDeque::with_capacity(max_batch_size),
            inject_at: None,
            started_at_block_number: latest_block_number,
            checkpoint_hash: latest_block_hash,
            highest_block_seen: latest_block_number,
            retry_count: 0,
            timeout_count: 0,
            empty_count: 0,
            headers_downloaded: 0,
            blocks_downloaded: 0,
        })
    }

    /// Skip Failure
    ///
    /// We get a plain ACK in certain cases - treated as an empty response.
    pub fn handle_acknowledgement(&mut self, from: PeerId) -> Result<()> {
        if let Some((peer, _)) = self.in_flight.as_ref() {
            // downgrade peer due to empty response
            if peer.peer_id == from {
                tracing::warn!(to = %peer.peer_id,
                    "sync::Acknowledgement : empty response"
                );
                self.empty_count = self.empty_count.saturating_add(1);

                self.peers
                    .done_with_peer(self.in_flight.take(), DownGrade::Empty);
                match self.state {
                    SyncState::Phase1(_) if Self::DO_SPECULATIVE => {
                        self.request_missing_metadata(None)?
                    }
                    // Retry if failed in Phase 2 for whatever reason
                    SyncState::Phase2(_) => self.state = SyncState::Retry1,
                    _ => {}
                }
            } else {
                tracing::warn!(to = %peer.peer_id,
                    "sync::Acknowledgement : spurious"
                );
            }
        }
        Ok(())
    }

    /// P2P Failure
    ///
    /// This gets called for any libp2p request failure - treated as a network failure
    pub fn handle_request_failure(&mut self, failure: OutgoingMessageFailure) -> Result<()> {
        // check if the request is a sync messages
        if let Some((peer, req_id)) = self.in_flight.as_ref() {
            // downgrade peer due to network failure
            if peer.peer_id == failure.peer && *req_id == failure.request_id {
                tracing::warn!(to = %peer.peer_id, err = %failure.error,
                    "sync::RequestFailure : network error"
                );
                self.timeout_count = self.timeout_count.saturating_add(1);

                self.peers
                    .done_with_peer(self.in_flight.take(), DownGrade::Timeout);
                match self.state {
                    SyncState::Phase1(_) if Self::DO_SPECULATIVE => {
                        self.request_missing_metadata(None)?
                    }
                    // Retry if failed in Phase 2 for whatever reason
                    SyncState::Phase2(_) => self.state = SyncState::Retry1,
                    _ => {}
                }
            } else {
                tracing::warn!(to = %peer.peer_id,
                    "sync::RequestFailure : spurious"
                );
            }
        }
        Ok(())
    }

    /// Phase 0: Sync a block proposal.
    ///
    /// This is the main entry point for active-syncing a block proposal.
    /// We start by enqueuing all proposals, and then check if the parent block exists in history.
    /// If the parent block exists, we do nothing. Otherwise, we check the least recent one.
    /// If we find its parent in history, we inject the entire queue. Otherwise, we start syncing.
    ///
    /// We do not perform checks on the Proposal here. This is done in the consensus layer.
    pub fn sync_from_proposal(&mut self, proposal: Proposal) -> Result<()> {
        // just stuff the latest proposal into the fixed-size queue.
        while self.recent_proposals.len() >= self.max_batch_size {
            self.recent_proposals.pop_front();
        }
        self.highest_block_seen = self.highest_block_seen.max(proposal.number());
        self.recent_proposals.push_back(proposal);

        self.internal_sync()
    }

    // TODO: Passive-sync place-holder - https://github.com/Zilliqa/zq2/issues/2232
    pub fn sync_to_genesis(&mut self) -> Result<()> {
        Ok(())
    }

    fn internal_sync(&mut self) -> Result<()> {
        if self.recent_proposals.is_empty() {
            // Do nothing if there's no recent proposals.
            tracing::debug!("sync::Internal : missing recent proposals");
            return Ok(());
        }

        match self.state {
            // Check if we are out of sync
            SyncState::Phase0 if self.in_pipeline == 0 => {
                let parent_hash = self.recent_proposals.back().unwrap().header.qc.block_hash;
                if !self.db.contains_block(&parent_hash)? {
                    // No parent block, trigger sync
                    tracing::info!("sync::SyncProposal : syncing from {parent_hash}",);
                    self.update_started_at()?;
                    // Ensure started_at_block_number is set before running this.
                    // https://github.com/Zilliqa/zq2/issues/2252#issuecomment-2636036676
                    let meta = self.recent_proposals.back().unwrap().header;
                    self.request_missing_metadata(Some(meta))?;
                }
            }
            // Continue phase 1, until we hit history/genesis.
            SyncState::Phase1(_) if self.in_pipeline < self.max_batch_size => {
                self.request_missing_metadata(None)?;
            }
            // Continue phase 2, until we have all segments.
            SyncState::Phase2(_) if self.in_pipeline < self.max_blocks_in_flight => {
                self.request_missing_blocks()?;
            }
            // Wait till 99% synced, zip it up!
            SyncState::Phase3 if self.in_pipeline == 0 => {
                let ancestor_hash = self.recent_proposals.front().unwrap().header.qc.block_hash;
                if self.db.contains_block(&ancestor_hash)? {
                    tracing::info!(
                        "sync::SyncProposal : finishing {} blocks for segment #{} from {}",
                        self.recent_proposals.len(),
                        self.db.count_sync_segments()?,
                        self.peer_id,
                    );
                    // inject the proposals
                    let proposals = self.recent_proposals.drain(..).collect_vec();
                    self.inject_proposals(proposals)?;
                }
                self.db.empty_sync_metadata()?;
                self.state = SyncState::Phase0;
            }
            // Retry to fix sync issues e.g. peers that are now offline
            SyncState::Retry1 if self.in_pipeline == 0 => {
                self.update_started_at()?;
                // Ensure started is updated - https://github.com/Zilliqa/zq2/issues/2306
                self.retry_phase1()?;
            }
            _ => {
                tracing::debug!("sync::SyncProposal : syncing {} blocks", self.in_pipeline);
            }
        }

        Ok(())
    }

    /// Update the startingBlock value.
    /// 
    /// Must be called before starting/re-starting Phase 1.
    fn update_started_at(&mut self) -> Result<()> {
        let highest_block = self
            .db
            .get_canonical_block_by_number(
                self.db
                    .get_highest_canonical_block_number()?
                    .expect("no highest block"),
            )?
            .expect("missing highest block");
        self.started_at_block_number = highest_block.number();
        Ok(())
    }

    /// Convenience function to convert a block to a proposal (add full txs)
    /// Should only be used for syncing history, not for consensus messages regarding new blocks.
    fn block_to_proposal(&self, block: Block) -> Proposal {
        // since block must be valid, unwrap(s) are safe
        let txs = block
            .transactions
            .iter()
            .map(|hash| self.db.get_transaction(hash).unwrap().unwrap())
            // handle verification on the client-side
            .map(|tx| {
                let hash = tx.calculate_hash();
                (tx, hash)
            })
            .collect_vec();
        Proposal::from_parts_with_hashes(block, txs)
    }

    /// Phase 2: Retry Phase 1
    ///
    /// If something went wrong in Phase 2, Phase 1 may need to be retried for the recently used segment.
    /// Things that could go wrong e.g. the peer went offline, the peer pruned history, etc.
    ///
    /// Pop the most recently used segment from the segment marker, and retry phase 1.
    /// This will rebuild history from the previous marker, with another peer.
    /// If this function is called many times, it will eventually restart from Phase 0.
    fn retry_phase1(&mut self) -> Result<()> {
        if self.db.count_sync_segments()? == 0 {
            tracing::error!("sync::RetryPhase1 : cannot retry phase 1 without chain segments!");
            self.state = SyncState::Phase0;
            return Ok(());
        }

        tracing::debug!(
            "sync::RetryPhase1 : retrying segment #{}",
            self.db.count_sync_segments()?,
        );
        self.retry_count = self.retry_count.saturating_add(1);

        // remove the last segment from the chain metadata
        let (meta, _) = self.db.last_sync_segment()?.unwrap();
        self.db.pop_sync_segment()?;
        self.state = SyncState::Phase1(meta);
        Ok(())
    }

    /// Phase 2: Handle a multi-block response.
    ///
    /// This is Phase 2 in the syncing algorithm, where we receive a set of blocks and inject them into the pipeline.
    /// We also remove the blocks from the chain metadata, because they are now in the pipeline.
    pub fn handle_multiblock_response(
        &mut self,
        from: PeerId,
        response: Vec<Proposal>,
    ) -> Result<()> {
        if let Some((peer, _)) = self.in_flight.as_ref() {
            if peer.peer_id != from {
                tracing::warn!(
                    "sync::MultiBlockResponse : unexpected peer={} != {from}",
                    peer.peer_id
                );
                return Ok(());
            }
        } else {
            tracing::warn!("sync::MultiBlockResponse : spurious response {from}");
            return Ok(());
        }

        // Process only a full response
        if response.is_empty() {
            // Empty response, downgrade peer and retry phase 1.
            tracing::warn!("sync::MultiBlockResponse : empty blocks {from}",);
            self.peers
                .done_with_peer(self.in_flight.take(), DownGrade::Empty);
            self.state = SyncState::Retry1;
            return Ok(());
        } else {
            self.peers
                .done_with_peer(self.in_flight.take(), DownGrade::None);
        }

        let SyncState::Phase2(check_sum) = self.state else {
            anyhow::bail!("sync::MultiBlockResponse : invalid state");
        };

        // If the checksum does not match, retry phase 1. Maybe the node has pruned the segment.
        let checksum = response
            .iter()
            .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, p| {
                sum.with(p.hash().as_bytes())
            })
            .finalize();

        if check_sum != checksum {
            tracing::error!(
                "sync::MultiBlockResponse : unexpected checksum={check_sum} != {checksum}"
            );
            self.state = SyncState::Retry1;
            return Ok(());
        }

        tracing::info!(
            "sync::MultiBlockResponse : received {} blocks for segment #{} from {}",
            response.len(),
            self.db.count_sync_segments()?,
            from
        );
        self.blocks_downloaded = self.blocks_downloaded.saturating_add(response.len() as u64);

        // Response seems sane.
        let proposals = response
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        self.db.pop_sync_segment()?;
        self.inject_proposals(proposals)?; // txns are verified when processing InjectedProposal.

        // Done with phase 2
        if self.db.count_sync_segments()? == 0 {
            self.state = SyncState::Phase3;
        } else if Self::DO_SPECULATIVE {
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

    /// Phase 2: Request missing blocks from the chain.
    ///
    /// It constructs a set of hashes, which constitute the series of blocks that are missing.
    /// These hashes are then sent to a Peer for retrieval.
    /// This is phase 2 of the syncing algorithm.
    fn request_missing_blocks(&mut self) -> Result<()> {
        if !matches!(self.state, SyncState::Phase2(_)) {
            anyhow::bail!("sync::RequestMissingBlocks : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if self.in_flight.is_some() || self.in_pipeline > self.max_blocks_in_flight {
            tracing::debug!(
                "sync::RequestMissingBlocks : syncing {}/{} blocks",
                self.in_pipeline,
                self.max_blocks_in_flight
            );
            return Ok(());
        }

        // will be re-inserted below
        if let Some(peer) = self.peers.get_next_peer() {
            // reinsert peer, as we will use a faux peer below, to force the request to go to the original responder
            self.peers.reinsert_peer(peer)?;

            // If we have no chain_segments, we have nothing to do
            if let Some((meta, peer_info)) = self.db.last_sync_segment()? {
                let request_hashes = self.db.get_sync_segment(meta.qc.block_hash)?;

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
                    self.db.count_sync_segments()?,
                    peer_info.peer_id,
                );
                let (peer_info, message) = match peer_info.version {
                    PeerVer::V2 => {
                        (
                            PeerInfo {
                                version: PeerVer::V2,
                                peer_id: peer_info.peer_id,
                                last_used: std::time::Instant::now(),
                                score: u32::MAX, // used to indicate faux peer, will not be added to the group of peers
                            },
                            ExternalMessage::MultiBlockRequest(request_hashes),
                        )
                    }
                    PeerVer::V1 => {
                        (
                            PeerInfo {
                                version: PeerVer::V1,
                                peer_id: peer_info.peer_id,
                                last_used: std::time::Instant::now(),
                                score: u32::MAX, // used to indicate faux peer, will not be added to the group of peers
                            },
                            // do not add VIEW_DRIFT - the stored marker is accurate!
                            ExternalMessage::BlockRequest(BlockRequest {
                                to_view: meta.view.saturating_sub(1),
                                from_view: meta.view.saturating_sub(self.max_batch_size as u64),
                            }),
                        )
                    }
                };
                let request_id = self
                    .message_sender
                    .send_external_message(peer_info.peer_id, message)?;
                self.in_flight = Some((peer_info, request_id));
            }
        } else {
            tracing::warn!("sync::RequestMissingBlocks : insufficient peers to handle request");
        }
        Ok(())
    }

    /// Phase 1 / 2: Handle a V1 block response
    ///
    /// If the response if from a V2 peer, it will upgrade that peer to V2.
    /// In phase 1, it will extract the metadata and feed it into handle_metadata_response.
    /// In phase 2, it will extract the blocks and feed it into handle_multiblock_response.
    pub fn handle_block_response(&mut self, from: PeerId, response: BlockResponse) -> Result<()> {
        // V2 response
        if response.availability.is_none()
            && response.proposals.is_empty()
            && response.from_view == u64::MAX
        {
            tracing::info!("sync::HandleBlockResponse : new response from {from}",);
            if let Some((mut peer, _)) = self.in_flight.take() {
                if peer.peer_id == from && peer.version == PeerVer::V1 {
                    // upgrade to V2 peer
                    peer.version = PeerVer::V2;
                    self.peers.reinsert_peer(peer)?;
                    match self.state {
                        SyncState::Phase2(_) => {
                            self.state = SyncState::Retry1;
                        }
                        SyncState::Phase1(_) if Self::DO_SPECULATIVE => {
                            self.request_missing_metadata(None)?;
                        }
                        _ => {}
                    }
                }
            }
            return Ok(());
        }

        tracing::trace!(
            "sync::HandleBlockResponse : received {} blocks from {from}",
            response.proposals.len()
        );

        // Convert the V1 response into a V2 response.
        match self.state {
            // Phase 1 - construct the metadata chain from the set of received proposals
            SyncState::Phase1(BlockHeader {
                number: block_number,
                qc:
                    QuorumCertificate {
                        block_hash: parent_hash,
                        ..
                    },
                ..
            }) => {
                // We do not buffer the proposals, as it takes 250MB/day!
                // Instead, we will re-request the proposals again, in Phase 2.
                let mut parent_hash = parent_hash;
                let metadata = response
                    .proposals
                    .into_iter()
                    // filter extras due to drift
                    .filter(|p| p.number() < block_number)
                    .sorted_by(|a, b| b.number().cmp(&a.number()))
                    // filter any forks
                    .filter(|p| {
                        if parent_hash != p.hash() {
                            return false;
                        }
                        parent_hash = p.header.qc.block_hash;
                        true
                    })
                    .map(|p| p.header)
                    .collect_vec();

                self.handle_metadata_response(from, metadata)?;
            }

            // Phase 2 - extract the requested proposals only.
            SyncState::Phase2(_) => {
                let multi_blocks = response
                    .proposals
                    .into_iter()
                    // filter any blocks that are not in the chain e.g. forks
                    .filter(|p| {
                        self.db
                            .contains_sync_metadata(&p.hash())
                            .unwrap_or_default()
                    })
                    .sorted_by(|a, b| b.number().cmp(&a.number()))
                    .collect_vec();

                self.handle_multiblock_response(from, multi_blocks)?;
            }
            _ => {
                tracing::error!(
                    "sync::HandleBlockResponse : from={from} response={:?}",
                    response
                );
            }
        }
        Ok(())
    }

    /// Phase 1: Handle a response to a metadata request.
    ///
    /// This is the first step in the syncing algorithm, where we receive a set of metadata and use it to
    /// construct a chain history. We check that the metadata does indeed constitute a segment of a chain.
    /// If it does, we record its segment marker and store the entire chain in-memory.
    pub fn handle_metadata_response(
        &mut self,
        from: PeerId,
        response: Vec<BlockHeader>,
    ) -> Result<()> {
        // Check for expected response
        let segment_peer = if let Some((peer, _)) = self.in_flight.as_ref() {
            if peer.peer_id != from {
                tracing::warn!(
                    "sync::MetadataResponse : unexpected peer={} != {from}",
                    peer.peer_id
                );
                return Ok(());
            }
            peer.clone()
        } else {
            // We ignore any responses that arrived late, since the original request has already 'timed-out'.
            tracing::warn!("sync::MetadataResponse : spurious response {from}");
            return Ok(());
        };

        // Process whatever we have received.
        if response.is_empty() {
            // Empty response, downgrade peer and retry with a new peer.
            tracing::warn!("sync::MetadataResponse : empty blocks {from}",);
            self.peers
                .done_with_peer(self.in_flight.take(), DownGrade::Empty);
            return Ok(());
        } else {
            self.peers
                .done_with_peer(self.in_flight.take(), DownGrade::None);
        }

        let SyncState::Phase1(meta) = &self.state else {
            anyhow::bail!("sync::MetadataResponse : invalid state");
        };

        // Check the linkage of the returned chain
        let mut block_hash = meta.qc.block_hash;
        let mut block_num = meta.number;
        for meta in response.iter() {
            // check that the block hash and number is as expected.
            if meta.hash != Hash::ZERO && block_hash == meta.hash && block_num == meta.number + 1 {
                block_hash = meta.qc.block_hash;
                block_num = meta.number;
            } else {
                // TODO: possibly, discard and rebuild entire chain
                // if something does not match, do nothing and retry the request with the next peer.
                tracing::error!(
                    "sync::MetadataResponse : unexpected metadata hash={block_hash} != {}, num={block_num} != {}",
                    meta.hash,
                    meta.number,
                );
                return Ok(());
            }
            if meta.hash == response.last().unwrap().hash {
                break; // done, we do not check the last parent, because that's outside this segment
            }
        }

        // Chain segment is sane
        let segment = response;

        // Record the constructed chain metadata
        self.db.insert_sync_metadata(&segment)?;

        // Record landmark(s), including peer that has this set of blocks
        self.db.push_sync_segment(&segment_peer, meta)?;

        tracing::info!(
            "sync::MetadataResponse : received {} metadata segment #{} from {}",
            segment.len(),
            self.db.count_sync_segments()?,
            from
        );
        self.headers_downloaded = self.headers_downloaded.saturating_add(segment.len() as u64);

        // TODO: Implement dynamic sub-segments - https://github.com/Zilliqa/zq2/issues/2158

        // Record the oldest block in the segment
        self.state = SyncState::Phase1(segment.last().cloned().unwrap());

        // If the check-point/starting-point is in this segment
        let checkpointed = segment.iter().any(|b| b.hash == self.checkpoint_hash);
        let turnaround = self.started_at_block_number >= segment.last().as_ref().unwrap().number;

        // If the segment hits our history, turnaround to Phase 2.
        if turnaround || checkpointed {
            self.state = SyncState::Phase2(Hash::ZERO);
        } else if Self::DO_SPECULATIVE {
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
        request: RequestBlocksByHeight,
    ) -> Result<ExternalMessage> {
        tracing::debug!(
            "sync::MetadataRequest : received a metadata request from {}",
            from
        );

        // Do not respond to stale requests as the client has probably timed-out
        if request.request_at.elapsed()? > Duration::from_secs(5) {
            tracing::warn!("sync::MetadataRequest : stale request");
            return Ok(ExternalMessage::Acknowledgement);
        }

        // TODO: Check if we should service this request - https://github.com/Zilliqa/zq2/issues/1878

        let batch_size: usize = self
            .max_batch_size
            .min(request.to_height.saturating_sub(request.from_height) as usize); // mitigate DOS by limiting the number of blocks we return
        let mut metas = Vec::with_capacity(batch_size);
        let Some(block) = self.db.get_canonical_block_by_number(request.to_height)? else {
            tracing::warn!("sync::MetadataRequest : unknown block height");
            return Ok(ExternalMessage::Acknowledgement);
        };
        metas.push(block.header);
        let mut hash = block.parent_hash();
        while metas.len() <= batch_size {
            // grab the parent
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            hash = block.parent_hash();
            metas.push(block.header);
        }

        let message = ExternalMessage::MetaDataResponse(metas);
        tracing::trace!(
            ?message,
            "sync::MetadataFromHash : responding to block request"
        );
        Ok(message)
    }

    /// Phase 1: Request chain metadata from a peer.
    ///
    /// This constructs a chain history by requesting blocks from a peer, going backwards from a given block.
    /// If Phase 1 is in progress, it continues requesting blocks from the last known Phase 1 block.
    /// Otherwise, it requests blocks from the given starting metadata.
    ///
    /// TODO: speed it up - https://github.com/Zilliqa/zq2/issues/2158
    pub fn request_missing_metadata(&mut self, meta: Option<BlockHeader>) -> Result<()> {
        if !matches!(self.state, SyncState::Phase1(_)) && !matches!(self.state, SyncState::Phase0) {
            anyhow::bail!("sync::RequestMissingMetadata : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if self.in_flight.is_some() || self.in_pipeline > self.max_batch_size {
            // anything more than this and we cannot be sure whether the segment hits history
            tracing::debug!(
                "sync::RequestMissingMetadata : syncing {}/{} blocks",
                self.in_pipeline,
                self.max_batch_size
            );
            return Ok(());
        }

        if let Some(peer_info) = self.peers.get_next_peer() {
            tracing::info!(
                "sync::RequestMissingMetadata : requesting {} metadata of segment #{} from {}",
                self.max_batch_size,
                self.db.count_sync_segments()? + 1,
                peer_info.peer_id
            );
            let message = match (self.state.clone(), &peer_info.version) {
                (
                    SyncState::Phase1(BlockHeader {
                        number: block_number,
                        ..
                    }),
                    PeerVer::V2,
                ) => ExternalMessage::MetaDataRequest(RequestBlocksByHeight {
                    request_at: SystemTime::now(),
                    to_height: block_number.saturating_sub(1),
                    from_height: block_number.saturating_sub(self.max_batch_size as u64),
                }),
                (
                    SyncState::Phase1(BlockHeader {
                        view: view_number, ..
                    }),
                    PeerVer::V1,
                ) => {
                    // For V1 BlockRequest, we request a little more than we need, due to drift
                    // Since the view number is an 'internal' clock, it is possible for the same block number
                    // to have different view numbers.
                    let drift = self.max_batch_size as u64 / 10;
                    ExternalMessage::BlockRequest(BlockRequest {
                        to_view: view_number.saturating_add(drift),
                        from_view: view_number.saturating_sub(self.max_batch_size as u64),
                    })
                }
                (SyncState::Phase0, PeerVer::V2) if meta.is_some() => {
                    let meta = meta.unwrap();
                    let block_number = meta.number;
                    self.state = SyncState::Phase1(meta);
                    ExternalMessage::MetaDataRequest(RequestBlocksByHeight {
                        request_at: SystemTime::now(),
                        to_height: block_number.saturating_sub(1),
                        from_height: block_number.saturating_sub(self.max_batch_size as u64),
                    })
                }
                (SyncState::Phase0, PeerVer::V1) if meta.is_some() => {
                    let meta = meta.unwrap();
                    let view_number = meta.view;
                    self.state = SyncState::Phase1(meta);
                    let drift = self.max_batch_size as u64 / 10;
                    ExternalMessage::BlockRequest(BlockRequest {
                        to_view: view_number.saturating_add(drift),
                        from_view: view_number.saturating_sub(self.max_batch_size as u64),
                    })
                }
                _ => anyhow::bail!("sync::MissingMetadata : invalid state"),
            };
            let request_id = self
                .message_sender
                .send_external_message(peer_info.peer_id, message)?;
            self.in_flight = Some((peer_info, request_id));
        } else {
            tracing::warn!("sync::RequestMissingBlocks : insufficient peers to handle request",);
        }
        Ok(())
    }

    /// Phase 2 / 3: Inject the proposals into the chain.
    ///
    /// It adds the list of proposals into the pipeline for execution.
    /// It also outputs some syncing statistics.
    fn inject_proposals(&mut self, proposals: Vec<Proposal>) -> Result<()> {
        if proposals.is_empty() {
            return Ok(());
        }

        // Output some stats
        if let Some((when, injected)) = self.inject_at {
            let diff = injected - self.in_pipeline;
            let rate = diff as f32 / when.elapsed().as_secs_f32();
            tracing::debug!("sync::InjectProposals : synced {} block/s", rate);
        }

        // Increment proposals injected
        self.in_pipeline = self.in_pipeline.saturating_add(proposals.len());
        tracing::debug!(
            "sync::InjectProposals : injecting {}/{} proposals",
            proposals.len(),
            self.in_pipeline
        );

        // Just pump the Proposals back to ourselves.
        for p in proposals {
            tracing::trace!(
                number = %p.number(), hash = %p.hash(),
                "sync::InjectProposals : applying",
            );
            self.message_sender.send_external_message(
                self.peer_id,
                ExternalMessage::InjectedProposal(InjectedProposal {
                    from: self.peer_id,
                    block: p,
                }),
            )?;
        }

        self.inject_at = Some((std::time::Instant::now(), self.in_pipeline));
        // return last proposal
        Ok(())
    }

    /// Mark a received proposal
    ///
    /// Mark a proposal as received, and remove it from the chain.
    pub fn mark_received_proposal(&mut self) -> Result<()> {
        self.in_pipeline = self.in_pipeline.saturating_sub(1);
        Ok(())
    }

    /// Returns (am_syncing, current_highest_block)
    pub fn am_syncing(&self) -> Result<bool> {
        Ok(self.in_pipeline != 0
            || !matches!(self.state, SyncState::Phase0)
            || self.db.count_sync_segments()? != 0)
    }

    // Returns (starting_block, current_block,  highest_block) if we're syncing,
    // None if we're not.
    pub fn get_sync_data(&self) -> Result<Option<SyncingStruct>> {
        if !self.am_syncing()? {
            return Ok(None);
        }

        let highest_block = self
            .db
            .get_canonical_block_by_number(
                self.db
                    .get_highest_canonical_block_number()?
                    .expect("no highest block"),
            )?
            .expect("missing highest block");

        let peers = if self.in_flight.is_some() {
            self.peers.count().saturating_add(1)
        } else {
            self.peers.count()
        };

        Ok(Some(SyncingStruct {
            starting_block: self.started_at_block_number,
            current_block: highest_block.number(),
            highest_block: self.highest_block_seen,
            status: SyncingMeta {
                peer_count: peers,
                current_phase: self.state.to_string(),
                retry_count: self.retry_count,
                timeout_count: self.timeout_count,
                empty_count: self.empty_count,
                header_downloads: self.headers_downloaded,
                block_downloads: self.blocks_downloaded,
                buffered_blocks: self.in_pipeline,
            },
        }))
    }

    /// Sets the checkpoint, if node was started from a checkpoint.
    pub fn set_checkpoint(&mut self, checkpoint: &Block) {
        let hash = checkpoint.hash();
        tracing::info!("sync::Checkpoint {}", hash);
        self.checkpoint_hash = hash;
    }
}

#[derive(Debug)]
pub struct SyncPeers {
    peer_id: PeerId,
    peers: Arc<Mutex<BinaryHeap<PeerInfo>>>,
}

impl SyncPeers {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            peers: Arc::new(Mutex::new(BinaryHeap::<PeerInfo>::new())),
        }
    }

    fn count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// Downgrade a peer based on the response received.
    ///
    /// This algorithm favours good peers that respond quickly (i.e. no timeout).
    /// In most cases, it eventually degenerates into 2 sources - avoid a single source of truth.
    fn done_with_peer(&self, in_flight: Option<(PeerInfo, RequestId)>, downgrade: DownGrade) {
        if let Some((mut peer, _)) = in_flight {
            tracing::trace!("sync::DoneWithPeer {} {:?}", peer.peer_id, downgrade);
            let mut peers = self.peers.lock().unwrap();
            peer.score = peer.score.saturating_add(downgrade as u32);
            if !peers.is_empty() {
                // Ensure that the next peer is equal or better
                peer.score = peer.score.max(peers.peek().unwrap().score);
            }
            // Reinsert peers that are good
            if peer.score < u32::MAX {
                peers.push(peer);
            }
        }
    }

    /// Add bulk peers
    pub fn add_peers(&self, peers: Vec<PeerId>) {
        tracing::debug!("sync::AddPeers {:?}", peers);
        peers
            .into_iter()
            .filter(|p| *p != self.peer_id)
            .for_each(|p| self.add_peer(p));
    }

    /// Add a peer to the list of peers.
    pub fn add_peer(&self, peer: PeerId) {
        let mut peers = self.peers.lock().unwrap();
        // if the new peer is not synced, it will get downgraded to the back of heap.
        // but by placing them at the back of the 'best' pack, we get to try them out soon.
        let new_peer = PeerInfo {
            version: PeerVer::V1,
            score: peers.iter().map(|p| p.score).min().unwrap_or_default(),
            peer_id: peer,
            last_used: Instant::now(),
        };
        // ensure that it is unique
        peers.retain(|p: &PeerInfo| p.peer_id != peer);
        peers.push(new_peer);

        tracing::trace!("sync::AddPeer {peer}/{}", peers.len());
    }

    /// Remove a peer from the list of peers.
    pub fn remove_peer(&self, peer: PeerId) {
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|p: &PeerInfo| p.peer_id != peer);
        tracing::trace!("sync::RemovePeer {peer}/{}", peers.len());
    }

    /// Get the next best peer to use
    fn get_next_peer(&self) -> Option<PeerInfo> {
        if let Some(mut peer) = self.peers.lock().unwrap().pop() {
            peer.last_used = std::time::Instant::now();
            tracing::trace!(peer = % peer.peer_id, score= %peer.score, "sync::GetNextPeer");
            return Some(peer);
        }
        None
    }

    /// Reinserts the peer such that it is at the front of the queue.
    fn reinsert_peer(&self, peer: PeerInfo) -> Result<()> {
        if peer.score == u32::MAX {
            return Ok(());
        }
        let mut peers = self.peers.lock().unwrap();
        let mut peer = peer;
        if !peers.is_empty() {
            // Ensure that it gets to the head of the line
            peer.last_used = peers
                .peek()
                .expect("peers.len() > 1")
                .last_used
                .checked_sub(Duration::from_secs(1))
                .expect("time is ordinal");
        }
        peers.push(peer);
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PeerInfo {
    pub score: u32,
    pub peer_id: PeerId,
    pub last_used: Instant,
    pub version: PeerVer,
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

/// For downgrading a peer from being selected in get_next_peer().
/// Ordered by degree of offence i.e. None is good, Timeout is worst
#[derive(Debug, Clone, Eq, PartialEq)]
enum DownGrade {
    None,
    Empty,
    Timeout,
}

impl Ord for DownGrade {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.clone() as u32).cmp(&(other.clone() as u32))
    }
}

impl PartialOrd for DownGrade {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Sync state
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum SyncState {
    Phase0,
    Phase1(BlockHeader),
    Phase2(Hash),
    Phase3,
    Retry1,
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncState::Phase0 => write!(f, "phase0"),
            SyncState::Phase1(_) => write!(f, "phase1"),
            SyncState::Phase2(_) => write!(f, "phase2"),
            SyncState::Phase3 => write!(f, "phase3"),
            SyncState::Retry1 => write!(f, "retry1"),
        }
    }
}

/// Peer Version
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PeerVer {
    V1 = 1,
    V2 = 2,
}

impl FromSql for PeerVer {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        u32::column_result(value).map(|i| match i {
            1 => PeerVer::V1,
            2 => PeerVer::V2,
            _ => todo!("invalid version"),
        })
    }
}

impl ToSql for PeerVer {
    fn to_sql(&self) -> Result<ToSqlOutput, rusqlite::Error> {
        Ok((self.clone() as u32).into())
    }
}
