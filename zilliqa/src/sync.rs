use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap, HashMap, VecDeque},
    ops::RangeInclusive,
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
        Proposal, RequestBlocksByHeight, SyncBlockHeader,
    },
    node::{MessageSender, OutgoingMessageFailure, RequestId},
    time::SystemTime,
};

// Syncing Algorithm
//
// When a Proposal is received by Consensus, we check if the parent exists in our DB.
// If not, then it triggers the active-syncing algorithm; else the passive-syncing algorithm.
/*
                                     +----------------------------+
                                     | PHASE-0: IDLE              |
+------------------------------------>                            <----------------------------------+
|                                    |                            |                                  |
|                                    +-++-------------------------+                                  |
|      Receives a normal proposal.     ||                                                            |
|     +--------------------------------+| Start syncing e.g. missing parent, or due to probe.        |
|     |                                 |                                                            |
|  +--v-------------------------+    +--v-------------------------+                                  |
|  | PHASE-4: PASSIVE HEADERS   |    | PHASE-1: ACTIVE HEADERS    |                                  |
|  |                            |    |                            <----------------+                 |
|  | Request 1-segment headers. |    | Request missing headers.   |                |                 |
|  +--+-------------------------+    +--+-------------------------+                |                 |
|     |                                 |                                          |                 |
|     | Receive requested segment.      | Received headers hits our history.       |                 |
|     |                                 |                                          |                 |
|  +--v-------------------------+    +--v-------------------------+             +--+--------------+  |
|  | PHASE-5: PASSIVE BLOCKS    |    | PHASE-2: ACTIVE BLOCKS     |             | RETRY-1: RETRY  |  |
|  |                            |    |                            |  on errors  |                 |  |
|  | Request 1-segment blocks.  |    | Request missing blocks.    +-------------> Retry 1-segment |  |
|  +--+-------------------------+    +--+-------------------------+             +-----------------+  |
|     |                                 |                                                            |
|     | Receive requested blocks.       | Receive all requested blocks.                              |
+-----+                                 |                                                            |
                                     +--v-------------------------+                                  |
                                     | PHASE-3: FINISH            |                                  |
                                     |                            +----------------------------------+
                                     | Inject cached segment.     |
                                     +----------------------------+
 */
//
// PHASE 1: Request missing chain headers.
// The entire chain of headers is stored in-memory, and is used to construct a chain of headers.
// 1. We start with the latest Proposal and request a segment of headers from a peer.
// 2. We construct the chain of headers, based on the response received.
// 3. If all headers are missing from our history, we request for more.
// 4. If any headers exist, we have hit our history, we move to Phase 2.
//
// PHASE 2: Request missing blocks.
// Once the chain of headers is constructed, we fill in the missing blocks to replay the history.
// 1. We construct a set of hashes, from the in-memory chain of headers.
// 2. We request these blocks from the same Peer that sent the headers.
// 3. We inject the received Proposals into the pipeline.
// 4. If there are still missing blocks, we ask for more.
// 5. If there are no more missing blocks, we move to Phase 3.
//
// PHASE 3: Zip it up.
// Phase 1&2 may run several times and bring up 99% of the chain, but it will never catch up.
// This closes the final gap.
// 1. We queue all recently received Proposals, while Phase 1 & 2 were in progress.
// 2. We extract a chain of Proposals from this queue.
// 3. If it does not link up to our history, we run Phase 1 again.
// 4. If it does, we inject the entire queue into the pipeline.
// 5. We are synced.
//
// PHASE4: Request archival headers.
// This is analogous to Phase 1, but we only request 1-segment worth of block headers.
// 1. We start with the lowest block in our chain, and request a segment of headers from a peer.
// 2. We construct the chain of headers, based on the response received.
// 3. We unconditionally move to Phase 5, to request the blocks.
//
// PHASE5: Request archival blocks.
// This is analogous to Phase 2, but we only request 1-segment worth of blocks.
// 1. We construct a set of hashes, from the in-memory chain of headers.
// 2. We request these blocks from the same Peer that sent the headers.
// 3. We store the blocks in the DB.
// 4. We unconditionally move to Phase 0, to wait for the next Proposal.

#[derive(Debug)]
pub struct Sync {
    // database
    db: Arc<Db>,
    // message bus
    message_sender: MessageSender,
    // internal peers
    peers: Arc<SyncPeers>,
    last_probe_at: Instant,
    cache_probe_response: Option<Proposal>, // cache the probe response
    // peers handling in-flight requests
    in_flight: VecDeque<(PeerInfo, RequestId)>,
    p1_response: BTreeMap<PeerId, Option<Vec<SyncBlockHeader>>>,
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
    inject_at: Option<(std::time::Instant, usize, u64)>,
    // record data for eth_syncing() RPC call.
    started_at: u64,
    highest_block_seen: u64,
    retry_count: usize,
    error_count: usize,
    empty_count: usize,
    headers_downloaded: usize,
    blocks_downloaded: usize,
    active_sync_count: usize,
    // internal structure for syncing
    segments: SyncSegments,
}

impl Sync {
    // Speed up by speculatively fetching blocks in Phase 1 & 2.
    const DO_SPECULATIVE: bool = true;
    // Speed up by fetching multiple segments in Phase 1.
    const MAX_CONCURRENT_PEERS: usize = 10;
    // Mitigate DoS
    const MAX_BATCH_SIZE: usize = 1000;

    pub fn new(
        config: &NodeConfig,
        db: Arc<Db>,
        latest_block: &Option<Block>,
        message_sender: MessageSender,
        peers: Arc<SyncPeers>,
    ) -> Result<Self> {
        let peer_id = message_sender.our_peer_id;
        let max_batch_size = config
            .sync
            .block_request_batch_size
            .clamp(100, Self::MAX_BATCH_SIZE);
        let max_blocks_in_flight = config
            .sync
            .max_blocks_in_flight
            .clamp(max_batch_size, Self::MAX_BATCH_SIZE);

        // Start from reset, or continue sync
        let latest_block_number = latest_block
            .as_ref()
            .map_or_else(|| u64::MIN, |b| b.number());

        Ok(Self {
            db,
            message_sender,
            peer_id,
            peers,
            max_batch_size,
            max_blocks_in_flight,
            in_flight: VecDeque::with_capacity(Self::MAX_CONCURRENT_PEERS),
            in_pipeline: usize::MIN,
            state: SyncState::Phase0,
            recent_proposals: VecDeque::with_capacity(max_batch_size),
            inject_at: None,
            started_at: latest_block_number,
            highest_block_seen: latest_block_number,
            retry_count: 0,
            error_count: 0,
            empty_count: 0,
            headers_downloaded: 0,
            blocks_downloaded: 0,
            active_sync_count: 0,
            p1_response: BTreeMap::new(),
            segments: SyncSegments::default(),
            cache_probe_response: None,
            last_probe_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(), // allow immediate sync at startup
        })
    }

    /// Skip Failure
    ///
    /// We get a plain ACK in certain cases - treated as an empty response.
    /// FIXME: Remove once all nodes upgraded to next version.
    pub fn handle_acknowledgement(&mut self, from: PeerId) -> Result<()> {
        self.empty_count = self.empty_count.saturating_add(1);
        if self.in_flight.iter().any(|(p, _)| p.peer_id == from) {
            tracing::warn!(%from, "sync::Acknowledgement");
            match &self.state {
                SyncState::Phase1(_) => {
                    self.handle_metadata_response(from, Some(vec![]))?;
                }
                SyncState::Phase2(_) => {
                    self.handle_multiblock_response(from, Some(vec![]))?;
                }
                state => {
                    tracing::error!(%state, "sync::Acknowledgement : invalid");
                }
            }
        }
        Ok(())
    }

    /// P2P Failure
    ///
    /// This gets called for any libp2p request failure - treated as a network failure
    pub fn handle_request_failure(
        &mut self,
        from: PeerId, // only to determine if self-triggered
        failure: OutgoingMessageFailure,
    ) -> Result<()> {
        self.error_count = self.error_count.saturating_add(1);
        if let Some((peer, _)) = self
            .in_flight
            .iter_mut()
            .find(|(p, r)| p.peer_id == failure.peer && *r == failure.request_id)
        {
            tracing::warn!(peer = %failure.peer, err=%failure.error, "sync::RequestFailure : failed");
            if !matches!(failure.error, libp2p::autonat::OutboundFailure::Timeout) {
                // drop the peer, in case of non-timeout errors
                peer.score = u32::MAX;
            }

            match &self.state {
                SyncState::Phase1(_) => {
                    self.handle_metadata_response(failure.peer, None)?;
                }
                SyncState::Phase2(_) => {
                    self.handle_multiblock_response(failure.peer, None)?;
                }
                state => {
                    tracing::error!(%state, %from, "sync::RequestFailure : invalid");
                }
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
        self.do_sync()
    }

    /// Phase 0: Sync from a probe.
    ///
    /// When invoked via NewView/manually, will trigger a probe to a peer to retrieve its latest block.
    /// The result is checked in `handle_block_response()`, and decision made to start syncing or not.
    pub fn sync_from_probe(&mut self) -> Result<()> {
        if self.am_syncing()? {
            // do not sync if we are already syncing
            tracing::debug!("sync::SyncFromProbe : already syncing");
            return Ok(());
        }
        // avoid spamming the network
        let elapsed = self.last_probe_at.elapsed();
        if elapsed < Duration::from_secs(60) {
            tracing::debug!(?elapsed, "sync::SyncFromProbe : skipping");
            return Ok(());
        } else {
            self.last_probe_at = Instant::now();
        }
        // inevitably picks a bootstrap node
        if let Some(peer_info) = self.peers.get_next_peer() {
            let peer = peer_info.peer_id;
            self.peers.append_peer(peer_info);
            tracing::info!(%peer, "sync::SyncFromProbe : probing");
            self.probe_peer(peer);
        } else {
            tracing::warn!("sync::SyncFromProbe: no more peers");
        }
        Ok(())
    }

    /// Drive the sync state-machine.
    fn do_sync(&mut self) -> Result<()> {
        if self.recent_proposals.is_empty() {
            // Do nothing if there's no recent proposals.
            tracing::debug!("sync::DoSync : missing recent proposals");
            return Ok(());
        }

        // check in-flights; manually failing one stale request.
        if !self.in_flight.is_empty() {
            let stale_flight = self
                .in_flight
                .iter()
                .find(|(p, _)| p.last_used.elapsed().as_secs() > 30) // triple default libp2p timeouts
                .cloned();
            if let Some((PeerInfo { peer_id: peer, .. }, request_id)) = stale_flight {
                tracing::warn!(%peer, ?request_id, "sync::DoSync : stale request");
                self.handle_request_failure(
                    self.peer_id, // self-triggered
                    OutgoingMessageFailure {
                        peer,
                        request_id,
                        error: libp2p::autonat::OutboundFailure::Timeout,
                    },
                )?;
            }
            return Ok(());
        }

        match self.state {
            // Check if we are out of sync
            SyncState::Phase0 if self.in_pipeline == 0 => {
                let meta = self.recent_proposals.back().unwrap().header;
                let parent_hash = meta.qc.block_hash;
                // No parent block, trigger active-sync
                if !self.db.contains_canonical_block(&parent_hash)? {
                    self.active_sync_count = self.active_sync_count.saturating_add(1);
                    tracing::debug!(from_hash = %parent_hash, "sync::DoSync : syncing",);
                    // Ensure started_at_block_number is set before running this.
                    // https://github.com/Zilliqa/zq2/issues/2252#issuecomment-2636036676
                    self.update_started_at()?;
                    self.request_missing_metadata(Some(meta))?;
                } else {
                    // one-block away from the tip, which can happen during a restart
                    self.state = SyncState::Phase3;
                    self.inject_recent_blocks()?;
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
                self.inject_recent_blocks()?;
            }
            // Retry to fix sync issues e.g. peers that are now offline
            SyncState::Retry1 if self.in_pipeline == 0 => {
                self.update_started_at()?;
                // Ensure started is updated - https://github.com/Zilliqa/zq2/issues/2306
                self.retry_phase1()?;
            }
            _ => {
                tracing::debug!("sync::DoSync : syncing {} blocks", self.in_pipeline);
            }
        }
        Ok(())
    }

    /// Injects the recent proposals
    ///
    /// The recent proposals have been buffering while active-sync is in process to 99%.
    /// This injects the last 1% to finish it up.
    fn inject_recent_blocks(&mut self) -> Result<()> {
        if !matches!(self.state, SyncState::Phase3) {
            anyhow::bail!("sync::RecentBlocks : invalid state");
        }
        // Only inject recent proposals - https://github.com/Zilliqa/zq2/issues/2520
        let highest_block = self
            .db
            .get_highest_recorded_block()?
            .expect("db is not empty");

        // drain, filter and sort cached-blocks.
        let proposals = self
            .recent_proposals
            .drain(..)
            .filter(|b| b.number() > highest_block.number()) // newer blocks
            .sorted_by(|a, b| match b.number().cmp(&a.number()) {
                Ordering::Equal => b.header.timestamp.cmp(&a.header.timestamp),
                o => o,
            }) // descending sort
            .collect_vec();

        if !proposals.is_empty() {
            // extract chain segment, ascending order
            let mut hash = proposals.first().expect("contains newer blocks").hash();
            let mut proposals = proposals
                .into_iter()
                .filter(|b| {
                    if b.hash() == hash {
                        hash = b.header.qc.block_hash; // find the parent
                        true
                    } else {
                        false
                    }
                })
                .collect_vec();
            proposals.reverse();

            // inject if it links up
            let ancestor_hash = proposals.first().expect(">= 1 block").header.qc.block_hash;
            let range = proposals.first().as_ref().unwrap().number()
                ..=proposals.last().as_ref().unwrap().number();
            tracing::info!(?range, "sync::DoSync : finishing");
            if self.db.contains_canonical_block(&ancestor_hash)? {
                self.inject_proposals(proposals)?;
            }
        }
        self.segments.empty_sync_metadata();
        self.state = SyncState::Phase0;
        Ok(())
    }

    /// Update the startingBlock value.
    ///
    /// Must be called before starting/re-starting Phase 1.
    fn update_started_at(&mut self) -> Result<()> {
        self.started_at = self
            .db
            .get_highest_canonical_block_number()?
            .expect("no highest canonical block");
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
        self.retry_count = self.retry_count.saturating_add(1);
        let segment_count = self.segments.count_sync_segments();
        if segment_count == 0 {
            tracing::error!("sync::Retry1 : no metadata segments");
            self.state = SyncState::Phase0;
            return Ok(());
        }

        tracing::debug!("sync::Retry1 : retrying segment #{segment_count}");

        // remove the last segment from the chain metadata
        let (meta, _) = self
            .segments
            .last_sync_segment()
            .expect("segment_count > 0");
        self.segments.pop_sync_segment();
        self.inject_at = None;
        self.state = SyncState::Phase1(meta);
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(())
    }

    /// Phase 2: Handle a multi-block response.
    ///
    /// This is Phase 2 in the syncing algorithm, where we receive a set of blocks and inject them into the pipeline.
    /// We also remove the blocks from the chain metadata, because they are now in the pipeline.
    pub fn handle_multiblock_response(
        &mut self,
        from: PeerId,
        response: Option<Vec<Proposal>>,
    ) -> Result<()> {
        let SyncState::Phase2(_) = &self.state else {
            tracing::warn!("sync::MultiBlockResponse : dropped response {from}");
            return Ok(());
        };
        if self.in_flight.is_empty() || self.in_flight.front().unwrap().0.peer_id != from {
            tracing::warn!("sync::MultiBlockResponse : spurious response {from}");
            return Ok(());
        }

        // Only process a full response
        if let Some(response) = response {
            if !response.is_empty() {
                let SyncState::Phase2((_, range)) = &self.state else {
                    unimplemented!("sync:MultiBlockResponse");
                };
                tracing::info!(?range, %from,
                    "sync::MultiBlockResponse : received",
                );
                self.blocks_downloaded = self.blocks_downloaded.saturating_add(response.len());
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::None);
                return self.do_multiblock_response(from, response); // successful 
            } else {
                // Empty response, downgrade peer and retry phase 1.
                tracing::warn!("sync::MultiBlockResponse : empty blocks {from}",);
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
            }
        } else {
            // Network failure, downgrade peer and retry phase 1.
            tracing::warn!(%from, "sync::MultiBlockResponse : error blocks",);
            self.peers
                .done_with_peer(self.in_flight.pop_front(), DownGrade::Error);
        }
        // failure fall-thru
        self.state = SyncState::Retry1;
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(())
    }

    fn do_multiblock_response(&mut self, from: PeerId, response: Vec<Proposal>) -> Result<()> {
        let SyncState::Phase2((check_sum, _)) = self.state else {
            anyhow::bail!("sync::MultiBlockResponse : invalid state");
        };

        // If the checksum does not match, retry phase 1. Maybe the node has pruned the segment.
        let computed_sum = response
            .iter()
            .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, p| {
                sum.with(p.hash().as_bytes())
            })
            .finalize();

        if check_sum != computed_sum {
            tracing::error!(
                "sync::MultiBlockResponse : unexpected checksum={check_sum} != {computed_sum} from {from}"
            );
            self.state = SyncState::Retry1;
            if Self::DO_SPECULATIVE {
                self.do_sync()?;
            }
            return Ok(());
        }

        // Response seems sane.
        let proposals = response
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        if self.inject_proposals(proposals)? {
            self.segments.pop_sync_segment();
        } else {
            // sync is stuck, cancel sync and restart, should be fast for peers that are already near the tip.
            self.state = SyncState::Phase3;
            return Ok(());
        };

        if self.segments.count_sync_segments() == 0 {
            self.state = SyncState::Phase3;
        }
        // perform next block transfers, where possible
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
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

        let batch_size: usize = Self::MAX_BATCH_SIZE.min(request.len()); // mitigate DOS by limiting the number of blocks we return
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
    /// ** MAKE ONLY ONE REQUEST AT A TIME **
    fn request_missing_blocks(&mut self) -> Result<()> {
        if !matches!(self.state, SyncState::Phase2(_)) {
            anyhow::bail!("sync::MissingBlocks : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if !self.in_flight.is_empty() || self.in_pipeline > self.max_blocks_in_flight {
            tracing::debug!(
                "sync::MissingBlocks : syncing {}/{} blocks",
                self.in_pipeline,
                self.max_blocks_in_flight
            );
            return Ok(());
        }

        // will be re-inserted below
        if let Some(peer) = self.peers.get_next_peer() {
            // reinsert peer, as we will use a faux peer below, to force the request to go to the original responder
            self.peers.reinsert_peer(peer);

            // If we have no chain_segments, we have nothing to do
            if let Some((meta, peer_info)) = self.segments.last_sync_segment() {
                let request_hashes = self.segments.get_sync_segment(&meta);

                // Checksum of the request hashes
                let checksum = request_hashes
                    .iter()
                    .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, h| {
                        sum.with(h.as_bytes())
                    })
                    .finalize();
                let range = self
                    .segments
                    .sync_block_number(request_hashes.last().as_ref().unwrap())
                    .unwrap()
                    ..=self
                        .segments
                        .sync_block_number(request_hashes.first().as_ref().unwrap())
                        .unwrap();

                // Fire request, to the original peer that sent the segment metadata
                tracing::info!(?range, from = %peer_info.peer_id,
                    "sync::MissingBlocks : requesting",
                );
                self.state = SyncState::Phase2((checksum, range));

                let message = ExternalMessage::MultiBlockRequest(request_hashes);
                let request_id = self
                    .message_sender
                    .send_external_message(peer_info.peer_id, message)?;
                self.add_in_flight(peer_info, request_id);
            } else {
                tracing::warn!("sync::MissingBlocks : no segments");
                self.state = SyncState::Phase3;
            }
        } else {
            tracing::warn!("sync::MissingBlocks : insufficient peers to handle request");
        }
        Ok(())
    }

    /// Phase 0: Handle a probe response
    ///
    /// Handle probe response:
    /// - Starts the sync-from-probe process.
    pub fn handle_block_response(
        &mut self,
        from: PeerId,
        mut response: BlockResponse,
    ) -> Result<()> {
        match self.state {
            // Start sync-from-probe
            SyncState::Phase0
                if response.availability.is_none() && !response.proposals.is_empty() =>
            {
                let proposal = response.proposals.pop().unwrap();
                if proposal.number() > self.started_at {
                    // inevitably from one of the bootstrap nodes
                    tracing::info!(self = %self.started_at, block = %proposal.number(), %from,
                        "sync::BlockResponse : probed, starting sync",
                    );
                    self.sync_from_proposal(proposal)?;
                } else {
                    tracing::info!(self = %self.started_at, block = %proposal.number(), %from,
                        "sync::BlockResponse : probed, not syncing",
                    );
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Handle probe request
    ///
    /// This is the first step in the syncing algorithm, where we receive a probe request and respond with the highest block we have.
    pub fn handle_block_request(
        &mut self,
        from: PeerId,
        request: BlockRequest,
    ) -> Result<ExternalMessage> {
        // probe message is BlockRequest::default()
        if request != BlockRequest::default() || from == self.peer_id {
            return Ok(ExternalMessage::Acknowledgement);
        }

        // Must have at least 1 block, genesis/checkpoint
        let block = self.db.get_highest_canonical_block()?.unwrap();

        tracing::info!(%from, number = %block.number(), "sync::BlockRequest : received probe");

        // send cached response
        if let Some(prop) = self.cache_probe_response.as_ref() {
            if prop.hash() == block.hash() {
                return Ok(ExternalMessage::BlockResponse(BlockResponse {
                    proposals: vec![prop.clone()],
                    from_view: u64::MAX,
                    availability: None,
                }));
            }
        };

        // Construct the proposal
        let prop = self.block_to_proposal(block);
        self.cache_probe_response = Some(prop.clone());
        let message = ExternalMessage::BlockResponse(BlockResponse {
            proposals: vec![prop],
            from_view: u64::MAX,
            availability: None,
        });
        Ok(message)
    }

    /// Phase 1: Handle a response to a metadata request.
    ///
    /// This is the first step in the syncing algorithm, where we receive a set of metadata and use it to
    /// construct a chain history. We check that the metadata does indeed constitute a segment of a chain.
    /// If it does, we record its segment marker and store the entire chain in-memory.
    pub fn handle_metadata_response(
        &mut self,
        from: PeerId,
        response: Option<Vec<SyncBlockHeader>>,
    ) -> Result<()> {
        let SyncState::Phase1(_) = &self.state else {
            tracing::warn!("sync::MetadataResponse : dropped response {from}");
            return Ok(());
        };
        if self.in_flight.is_empty() {
            tracing::warn!("sync::MetadataResponse : spurious response {from}");
            return Ok(());
        }

        // buffer response for processing
        self.p1_response.insert(from, response);

        // process responses, in-order
        while let Some((peer, _)) = self.in_flight.front() {
            if self.p1_response.contains_key(&peer.peer_id) {
                let peer_id = peer.peer_id;
                let response = self.p1_response.remove(&peer_id).unwrap();
                // Only process a full response
                if let Some(response) = response {
                    if !response.is_empty() {
                        let range = response.last().unwrap().header.number
                            ..=response.first().unwrap().header.number;
                        tracing::info!(?range, from = %peer_id,
                            "sync::MetadataResponse : received",
                        );
                        self.headers_downloaded =
                            self.headers_downloaded.saturating_add(response.len());
                        let peer = peer.clone();

                        if response.len() == self.max_batch_size {
                            self.peers
                                .done_with_peer(self.in_flight.pop_front(), DownGrade::None);
                        } else {
                            // downgrade peers that cannot fulfill request range
                            self.peers
                                .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
                        }

                        self.do_metadata_response(peer, response)?;
                        continue;
                    } else {
                        // Empty response
                        tracing::warn!("sync::MetadataResponse : empty from {peer_id}");
                        self.peers
                            .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
                    }
                } else {
                    // Network failure, downgrade peer and retry.
                    tracing::warn!("sync::MetadataResponse : error from {peer_id}");
                    self.peers
                        .done_with_peer(self.in_flight.pop_front(), DownGrade::Error);
                }
                // failure fall-thru - fire one request
                self.do_missing_metadata(None, 1)?;
                if !self.in_flight.is_empty() {
                    self.in_flight.rotate_right(1); // adjust request order, do_missing_metadata() pushes peer to the back.
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    fn do_metadata_response(
        &mut self,
        segment_peer: PeerInfo,
        response: Vec<SyncBlockHeader>,
    ) -> Result<()> {
        let SyncState::Phase1(meta) = &self.state else {
            anyhow::bail!("sync::DoMetadataResponse : invalid state");
        };

        if response.is_empty() {
            return Ok(());
        }

        // Check the linkage of the returned chain
        let mut block_hash = meta.qc.block_hash;
        let mut block_num = meta.number;
        for SyncBlockHeader { header: meta, .. } in response.iter() {
            // check that the block hash and number is as expected.
            if meta.hash != Hash::ZERO && block_hash == meta.hash && block_num == meta.number + 1 {
                block_hash = meta.qc.block_hash;
                block_num = meta.number;
            } else {
                // If something does not match, restart from the last known segment.
                // This is a safety mechanism to prevent a peer from sending us garbage.
                tracing::error!(
                    "sync::DoMetadataResponse : unexpected metadata hash={block_hash} != {}, num={block_num} != {}",
                    meta.hash,
                    meta.number,
                );
                // Unless, it is the first segment, where it will restart the entire sync.
                // https://github.com/Zilliqa/zq2/issues/2416
                if self.segments.count_sync_segments() <= 1 {
                    self.state = SyncState::Phase3; // flush, drop all segments, and restart
                    self.p1_response.clear();
                    for p in self.in_flight.drain(..) {
                        self.peers.done_with_peer(Some(p), DownGrade::None);
                    }
                }
                return Ok(());
            }
            if meta.hash == response.last().unwrap().header.hash {
                break; // done, we do not check the last parent, because that's outside this segment
            }
        }

        // Chain segment is sane, drop redundant blocks already in the DB.
        let mut drop = false;
        let response = response
            .into_iter()
            .filter(|b| {
                drop |= self
                    .db
                    .contains_canonical_block(&b.header.hash)
                    .unwrap_or_default();
                !drop
            })
            .collect_vec();
        let segment = response.iter().map(|sb| sb.header).collect_vec();

        let turnaround = if !segment.is_empty() {
            // Record the constructed chain metadata
            self.segments.insert_sync_metadata(&segment);

            // Record landmark(s), including peer that has this set of blocks
            self.segments.push_sync_segment(&segment_peer, meta);

            // Dynamic sub-segments - https://github.com/Zilliqa/zq2/issues/2312
            let mut block_size: usize = 0;
            for SyncBlockHeader { header, .. } in response.iter().rev().filter(|&sb| {
                // The segment markers are computed in ascending order, so that the segment markers are always outside the segment.
                block_size = block_size.saturating_add(sb.size_estimate);
                tracing::trace!(total=%block_size, "sync::MetadataResponse : response size estimate");
                // Do not overflow libp2p::request-response::cbor::codec::RESPONSE_SIZE_MAXIMUM = 10MB (default)
                // Try to fill up >90% of RESPONSE_SIZE_MAXIMUM.
                if block_size > 9 * 1024 * 1024 {
                    block_size = 0;
                    true
                } else {
                    false
                }
            }).rev() {
                // segment markers are inserted in descending order, which is the order in the stack.
                self.segments.push_sync_segment(&segment_peer, header);
            }

            // Record the oldest block in the segment
            self.state = SyncState::Phase1(segment.last().cloned().unwrap());

            // Check if the segment hits our history
            let block_hash = segment.last().as_ref().unwrap().qc.block_hash;
            self.db
                .contains_canonical_block(&block_hash)
                .unwrap_or_default()
        } else {
            true
        };

        if turnaround {
            // turnaround to Phase 2.
            self.state = SyncState::Phase2((Hash::ZERO, 0..=0));
            // drop all pending requests & responses
            self.p1_response.clear();
            for p in self.in_flight.drain(..) {
                self.peers.done_with_peer(Some(p), DownGrade::None);
            }
        }

        // perform next block transfers, where possible
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
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
        let range = request.from_height..=request.to_height;
        tracing::debug!(?range, %from,
            "sync::MetadataRequest : received",
        );

        // Do not respond to stale requests as the client has probably timed-out
        if request.request_at.elapsed()?.as_secs() > 20 {
            tracing::warn!("sync::MetadataRequest : stale request");
            return Ok(ExternalMessage::MetaDataResponse(vec![]));
        }

        // TODO: Check if we should service this request - https://github.com/Zilliqa/zq2/issues/1878

        let batch_size = Self::MAX_BATCH_SIZE
            .min(request.to_height.saturating_sub(request.from_height) as usize);
        let mut metas = Vec::with_capacity(batch_size);
        let Some(block) = self.db.get_canonical_block_by_number(request.to_height)? else {
            tracing::warn!("sync::MetadataRequest : unknown block height");
            return Ok(ExternalMessage::SyncBlockHeaders(vec![]));
        };

        let mut hash = block.hash();
        while metas.len() <= batch_size {
            // grab the parent
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            hash = block.parent_hash();

            let proposal = self.block_to_proposal(block.clone());
            let encoded_size = cbor4ii::serde::to_vec(Vec::new(), &proposal)?.len();

            // insert the sync size
            metas.push(SyncBlockHeader {
                header: block.header,
                size_estimate: encoded_size,
            });
        }

        let message = ExternalMessage::SyncBlockHeaders(metas);
        Ok(message)
    }

    /// Phase 1: Request chain metadata from a peer.
    ///
    /// This constructs a chain history by requesting blocks from a peer, going backwards from a given block.
    /// If Phase 1 is in progress, it continues requesting blocks from the last known Phase 1 block.
    /// Otherwise, it requests blocks from the given starting metadata.
    pub fn request_missing_metadata(&mut self, meta: Option<BlockHeader>) -> Result<()> {
        if !matches!(self.state, SyncState::Phase1(_)) && !matches!(self.state, SyncState::Phase0) {
            anyhow::bail!("sync::RequestMissingMetadata : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if !self.in_flight.is_empty() || self.in_pipeline > self.max_batch_size {
            // anything more than this and we cannot be sure whether the segment hits history
            tracing::debug!(
                "sync::RequestMissingMetadata : syncing {}/{} blocks",
                self.in_pipeline,
                self.max_batch_size
            );
            return Ok(());
        }

        let good_count = self.peers.count_good_peers();
        let peer_count = self.peers.count();
        let peer_set = if good_count > Self::MAX_CONCURRENT_PEERS {
            Self::MAX_CONCURRENT_PEERS // ideal case, more than enough good peers
        } else if good_count > 1 {
            good_count.saturating_sub(1) // leave one spare, for handling issues; eventually degenerates to 1-peer
        } else if peer_count > Self::MAX_CONCURRENT_PEERS {
            Self::MAX_CONCURRENT_PEERS // then, retry with non-good ones too; trying to bump up peers
        } else if peer_count > 1 {
            peer_count.saturating_sub(1) // leave one spare, for handling issues.
        } else {
            peer_count // last ditch effort, with only 1-peer (or none)
        };

        if peer_set == 0 {
            tracing::warn!("sync::RequestMissingMetadata : no peers to handle request");
            return Ok(());
        }

        self.do_missing_metadata(meta, peer_set)
    }

    /// Phase 1: Request chain metadata from a peer.
    ///
    /// This fires concurrent requests to N peers, to fetch different segments of chain metadata.
    /// The number of requests is limited by:
    /// - the number of good peers
    /// - hitting the starting point
    /// - encountering a V1 peer
    fn do_missing_metadata(&mut self, meta: Option<BlockHeader>, num_peers: usize) -> Result<()> {
        if !matches!(self.state, SyncState::Phase1(_)) && !matches!(self.state, SyncState::Phase0) {
            anyhow::bail!("sync::DoMissingMetadata : invalid state");
        }
        let mut offset = u64::MIN;
        for num in 1..=num_peers {
            if let Some(peer_info) = self.peers.get_next_peer() {
                let (message, done, range) = match (&self.state, &peer_info.version) {
                    (
                        SyncState::Phase1(BlockHeader {
                            number: block_number,
                            ..
                        }),
                        PeerVer::V2,
                    ) => {
                        let range = block_number
                            .saturating_sub(offset)
                            .saturating_sub(self.max_batch_size as u64)
                            ..=block_number.saturating_sub(offset).saturating_sub(1);
                        let message = ExternalMessage::MetaDataRequest(RequestBlocksByHeight {
                            request_at: SystemTime::now(),
                            to_height: *range.end(),
                            from_height: *range.start(),
                        });
                        (message, *range.start() < self.started_at, range)
                    }
                    (SyncState::Phase0, PeerVer::V2) if meta.is_some() => {
                        let meta = meta.unwrap();
                        let block_number = meta.number;
                        let range = block_number
                            .saturating_sub(offset)
                            .saturating_sub(self.max_batch_size as u64)
                            ..=block_number.saturating_sub(offset).saturating_sub(1);
                        self.state = SyncState::Phase1(meta);
                        let message = ExternalMessage::MetaDataRequest(RequestBlocksByHeight {
                            request_at: SystemTime::now(),
                            to_height: *range.end(),
                            from_height: *range.start(),
                        });
                        (message, *range.start() < self.started_at, range)
                    }
                    _ => unimplemented!("sync::DoMissingMetadata"),
                };

                tracing::info!(?range, from = %peer_info.peer_id,
                    "sync::MissingMetadata : requesting ({num}/{num_peers})",
                );
                let count = range.count();
                offset = offset.saturating_add(count as u64);

                let request_id = self
                    .message_sender
                    .send_external_message(peer_info.peer_id, message)?;
                self.add_in_flight(peer_info, request_id);

                if done {
                    break;
                }
            } else {
                tracing::warn!("sync::DoMissingMetadata : insufficient peers to handle request");
                break;
            }
        }
        Ok(())
    }

    /// Phase 2 / 3: Inject the proposals into the chain.
    ///
    /// It adds the list of proposals into the pipeline for execution.
    /// It also outputs some syncing statistics.
    fn inject_proposals(&mut self, proposals: Vec<Proposal>) -> Result<bool> {
        if proposals.is_empty() {
            return Ok(true);
        }

        let highest_number = self
            .db
            .get_highest_canonical_block_number()?
            .unwrap_or_default();

        // Output some stats
        if let Some((when, injected, prev_highest)) = self.inject_at {
            let diff = injected - self.in_pipeline;
            let rate = diff as f32 / when.elapsed().as_secs_f32();
            tracing::debug!(%rate, "sync::InjectProposals : injected");
            // Detect if node is stuck i.e. active-sync is not making progress
            if highest_number == prev_highest
                && proposals
                    .first()
                    .unwrap()
                    .number()
                    .saturating_sub(self.max_blocks_in_flight as u64)
                    .saturating_sub(self.in_pipeline as u64)
                    .gt(&highest_number)
            {
                tracing::warn!("sync::InjectProposals : node is stuck at {prev_highest}");
                return Ok(false);
            }
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

        self.inject_at = Some((std::time::Instant::now(), self.in_pipeline, highest_number));
        Ok(true)
    }

    /// Mark a received proposal
    ///
    /// Mark a proposal as received, and remove it from the chain.
    pub fn mark_received_proposal(&mut self, number: u64) -> Result<()> {
        tracing::trace!(%number, "sync::MarkReceivedProposal : received");
        self.in_pipeline = self.in_pipeline.saturating_sub(1);
        // perform next block transfers, where possible
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(())
    }

    /// Returns (am_syncing, current_highest_block)
    pub fn am_syncing(&self) -> Result<bool> {
        Ok(self.in_pipeline != 0
            || !matches!(self.state, SyncState::Phase0)
            || self.segments.count_sync_segments() != 0)
    }

    // Returns (starting_block, current_block,  highest_block) if we're syncing,
    // None if we're not.
    pub fn get_sync_data(&self) -> Result<Option<SyncingStruct>> {
        if !self.am_syncing()? {
            return Ok(None);
        }

        let current_block = self
            .db
            .get_highest_canonical_block_number()?
            .expect("no highest block");

        let peer_count = self.peers.count() + self.in_flight.len();

        Ok(Some(SyncingStruct {
            starting_block: self.started_at,
            current_block,
            highest_block: self.highest_block_seen,
            stats: SyncingMeta {
                peer_count,
                current_phase: self.state.to_string(),
                retry_count: self.retry_count,
                error_count: self.error_count,
                empty_count: self.empty_count,
                header_downloads: self.headers_downloaded,
                block_downloads: self.blocks_downloaded,
                buffered_blocks: self.in_pipeline,
                active_sync_count: self.active_sync_count,
            },
        }))
    }

    /// Sets the checkpoint, if node was started from a checkpoint.
    pub fn set_checkpoint(&mut self, _checkpoint: &Block) {
        tracing::debug!("sync::Checkpoint");
    }

    // Add an in-flight request
    fn add_in_flight(&mut self, peer_info: PeerInfo, request_id: RequestId) {
        self.in_flight.push_back((peer_info, request_id));
    }

    // Fired from both [Self::sync_from_probe(); and [Consensus::sync_from_probe()] test.
    pub fn probe_peer(&mut self, peer: PeerId) {
        self.message_sender
            .send_external_message(peer, ExternalMessage::BlockRequest(BlockRequest::default()))
            .ok(); // ignore errors, retry with subsequent peer(s).
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

    /// Count the number of good peers
    pub fn count_good_peers(&self) -> usize {
        let peers = self.peers.lock().unwrap();
        if peers.is_empty() {
            return 0;
        }
        let best_score = peers.iter().map(|p| p.score).min().unwrap();
        let best_count = peers.iter().filter(|p| p.score == best_score).count();

        best_count // optimistic, use as many peers as possible
    }

    fn count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// Downgrade a peer based on the response received.
    ///
    /// This algorithm favours good peers that respond quickly (i.e. no timeout).
    /// In most cases, it eventually degenerates into 2 sources - avoid a single source of truth.
    fn done_with_peer(&self, in_flight: Option<(PeerInfo, RequestId)>, downgrade: DownGrade) {
        if in_flight.is_none() {
            return;
        }
        let (mut peer, _) = in_flight.unwrap();
        tracing::trace!("sync::DoneWithPeer {} {:?}", peer.peer_id, downgrade);
        // Reinsert peers that are good
        if peer.score < u32::MAX {
            peer.score = peer.score.saturating_add(downgrade as u32);
            self.append_peer(peer);
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
            version: PeerVer::V2, // default to V2 since >= 0.7.0
            score: peers.iter().map(|p| p.score).min().unwrap_or_default(),
            peer_id: peer,
            last_used: Instant::now(),
        };
        // ensure that it is unique
        peers.retain(|p| p.peer_id != peer);
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

    /// Reinserts the peer such that it is at the back of the good queue.
    fn append_peer(&self, mut peer: PeerInfo) {
        if peer.score == u32::MAX {
            return;
        }
        let mut peers = self.peers.lock().unwrap();
        if !peers.is_empty() {
            // Ensure that the next peer is equal or better
            peer.score = peer.score.max(peers.peek().unwrap().score);
        }
        peers.retain(|p| p.peer_id != peer.peer_id);
        peers.push(peer);
    }

    /// Reinserts the peer such that it is at the front of the good queue.
    fn reinsert_peer(&self, mut peer: PeerInfo) {
        if peer.score == u32::MAX {
            return;
        }
        let mut peers = self.peers.lock().unwrap();
        if !peers.is_empty() {
            // Ensure that it gets to the head of the line
            peer.last_used = peers
                .peek()
                .expect("peers.len() > 1")
                .last_used
                .checked_sub(Duration::from_secs(1))
                .expect("time is ordinal");
        }
        // ensure that it is unique
        peers.retain(|p| p.peer_id != peer.peer_id);
        peers.push(peer);
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
    Error,
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
    Phase2((Hash, RangeInclusive<u64>)),
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
///
/// It identifies the form of sync algorithm that is supported by a peer. We assume that all peers are V1 at first.
/// At the first encounter with a peer, it is probed and its response determines if it is treated as a V1/V2 peer.
/// We have deprecated support for V1 peers. So, V1 now really means 'unknown' peer version.
///
/// V1 - peers that support original sync algorithm in `block_store.rs`
/// V2 - peers that support new sync algorithm in `sync.rs`
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

#[derive(Debug, Default)]
struct SyncSegments {
    headers: HashMap<Hash, BlockHeader>,
    segments: Vec<(Hash, PeerInfo)>,
}

impl SyncSegments {
    /// Returns the lowest block number of stored sync segments
    fn sync_block_number(&self, hash: &Hash) -> Option<u64> {
        self.headers.get(hash).map(|h| h.number)
    }

    /// Returns the number of stored sync segments
    fn count_sync_segments(&self) -> usize {
        self.segments.len()
    }

    /// Retrieves bulk metadata information from the given block_hash (inclusive)
    fn get_sync_segment(&self, block: &BlockHeader) -> Vec<Hash> {
        let mut result = vec![];

        let mut hash = block.qc.block_hash;
        // This implementation skips the final segment in the chain.
        // By design, the marker for the segment is always outside the segment.
        // empty_sync_metadata() will remove the final marker.
        while let Some(header) = self.headers.get(&hash) {
            result.push(header.hash);
            hash = header.qc.block_hash;
        }

        result
    }

    /// Peeks into the top of the segment stack.
    fn last_sync_segment(&self) -> Option<(BlockHeader, PeerInfo)> {
        let (hash, peer) = self.segments.last()?;
        let header = self.headers.get(hash).cloned()?;
        let peer = PeerInfo {
            last_used: Instant::now(),
            score: u32::MAX,
            ..peer.clone()
        };
        Some((header, peer))
    }

    /// Pushes a particular segment into the stack.
    fn push_sync_segment(&mut self, peer: &PeerInfo, meta: &BlockHeader) {
        self.headers.insert(meta.hash, *meta);
        self.segments.push((meta.hash, peer.clone()));
    }

    /// Bulk inserts a bunch of metadata.
    fn insert_sync_metadata(&mut self, metas: &Vec<BlockHeader>) {
        for meta in metas {
            self.headers.insert(meta.hash, *meta);
        }
    }

    /// Empty the metadata table.
    fn empty_sync_metadata(&mut self) {
        self.segments.clear();
        self.headers.clear();
    }

    /// Pops a segment from the stack; and bulk removes all metadata associated with it.
    fn pop_sync_segment(&mut self) {
        let (hash, _) = self.segments.pop().expect("non-empty stack");
        let header = self.headers.get(&hash).unwrap();
        let mut hash = header.qc.block_hash;
        while let Some(h) = self.headers.remove(&hash) {
            hash = h.qc.block_hash;
        }
    }
}
