use std::{
    cmp::{Ordering, Reverse},
    collections::{BTreeMap, BinaryHeap, HashMap, VecDeque},
    ops::RangeInclusive,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use itertools::Itertools;
use libp2p::PeerId;
use rand::Rng;
use rusqlite::types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

use crate::{
    api::types::eth::{SyncingMeta, SyncingStruct},
    cfg::NodeConfig,
    crypto::Hash,
    db::Db,
    message::{
        Block, BlockHeader, BlockRequest, BlockResponse, ExternalMessage, InjectedProposal,
        PassiveSyncRequest, PassiveSyncResponse, Proposal, RequestBlocksByHeight, SyncBlockHeader,
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
    // how many blocks to request/prune at once
    max_batch_size: usize,
    prune_interval: u64,
    prune_timeout_ms: u128,
    // how many blocks to inject into the queue
    max_blocks_in_flight: usize,
    // count of proposals pending in the pipeline
    in_pipeline: usize,
    // our peer id
    peer_id: PeerId,
    is_validator: bool,
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
    passive_sync_count: usize,
    // internal structure for syncing
    segments: SyncSegments,
    size_cache: HashMap<Hash, usize>,
    // passive sync
    sync_base_height: u64,
}

impl Sync {
    // Speed up by speculatively fetching blocks in Phase 1 & 2.
    const DO_SPECULATIVE: bool = true;
    // Speed up by fetching multiple segments in Phase 1.
    const MAX_CONCURRENT_PEERS: usize = 10;
    // Mitigate DoS
    const MAX_BATCH_SIZE: usize = 1000;
    // Cache recent blocks
    const MAX_CACHE_SIZE: usize = 10000;

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
        let sync_base_height = config.sync.sync_base_height;
        let prune_interval = config.sync.prune_interval;
        // Start from reset, or continue sync
        let latest_block_number = latest_block
            .as_ref()
            .map_or_else(|| u64::MIN, |b| b.number());

        // If set, sync_base_height must be sane
        if sync_base_height != u64::MAX && latest_block_number < sync_base_height {
            return Err(anyhow::anyhow!("sync_base_height > highest_block"));
        }

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
            passive_sync_count: 0,
            p1_response: BTreeMap::new(),
            segments: SyncSegments::default(),
            cache_probe_response: None,
            last_probe_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(), // allow immediate sync at startup
            sync_base_height,
            prune_interval,
            is_validator: true, // assume true on restart, until next epoch
            prune_timeout_ms: 0,
            size_cache: HashMap::with_capacity(Self::MAX_CACHE_SIZE),
        })
    }

    pub fn set_validator(&mut self, is_validator: bool) {
        tracing::trace!(peer_id = %self.peer_id, %is_validator, "sync::SetValidator");
        self.is_validator = is_validator;
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
                SyncState::Phase4(_) => todo!(),
                SyncState::Phase1(_) => {
                    self.handle_active_response(from, Some(vec![]))?;
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
                SyncState::Phase4(_) => todo!(),
                SyncState::Phase1(_) => {
                    self.handle_active_response(failure.peer, None)?;
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

    pub fn set_prune_timeout(&mut self, timeout_ms: u64) {
        self.prune_timeout_ms = timeout_ms as u128;
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
                .find(|(p, _)| p.last_used.elapsed().as_secs() > 90) // 9x libp2p timeout
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

        tracing::trace!(state = %self.state, "sync::DoSync");

        match self.state {
            // Check if we are out of sync
            SyncState::Phase0 if self.in_pipeline == 0 => {
                let meta = &self.recent_proposals.back().unwrap().header;
                if self.db.contains_canonical_block(&meta.hash)? {
                    // We have the latest block, trigger passive-sync
                    self.start_passive_sync()?;
                } else if !self.db.contains_canonical_block(&meta.qc.block_hash)? {
                    // We don't have the parent block, trigger active-sync
                    self.start_active_sync(*meta)?;
                }
                // could be a fork, wait for another proposal
            }
            // Continue phase 1, until we hit history/genesis.
            SyncState::Phase1(_) if self.in_pipeline < self.max_batch_size => {
                self.request_missing_headers()?;
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
            SyncState::Retry1(_) if self.in_pipeline == 0 => {
                self.update_started_at()?;
                // Ensure started is updated - https://github.com/Zilliqa/zq2/issues/2306
                self.retry_phase1()?;
            }
            SyncState::Phase4(_) => todo!(),
            _ => {
                tracing::debug!(in_pipeline = %self.in_pipeline, "sync::DoSync : syncing");
            }
        }
        Ok(())
    }

    /// Phase 0: Start Active Sync
    ///
    /// Given a block header, start the active sync process from that point going backwards.
    fn start_active_sync(&mut self, meta: BlockHeader) -> Result<()> {
        if !matches!(self.state, SyncState::Phase0) {
            unimplemented!("sync::StartActiveSync : invalid state");
        }
        // No parent block, trigger active-sync
        self.active_sync_count = self.active_sync_count.saturating_add(1);
        tracing::debug!(from_hash = %meta.qc.block_hash, "sync::StartActiveSync : syncing",);
        // Ensure started_at_block_number is set before running this.
        // https://github.com/Zilliqa/zq2/issues/2252#issuecomment-2636036676
        self.update_started_at()?;
        self.state = SyncState::Phase1(meta);
        self.request_missing_headers()?;
        Ok(())
    }

    /// Phase 0: Start Passive Sync
    ///
    /// Starts passive sync from the lowest block in the DB, back to the sync-base-height.
    /// It also prunes any blocks lower than sync-base-height.
    fn start_passive_sync(&mut self) -> Result<()> {
        if !matches!(self.state, SyncState::Phase0) {
            unimplemented!("sync::StartPassiveSync : invalid state");
        }

        if self.sync_base_height == u64::MAX && self.prune_interval == u64::MAX {
            return Ok(());
        }

        let range = self.db.available_range()?;

        match (*range.start()).cmp(&self.sync_base_height) {
            // done, turn off passive-sync
            Ordering::Equal => {
                self.sync_base_height = u64::MAX;
            }
            // passive-sync above sync-base-height
            Ordering::Greater => {
                tracing::debug!(?range, "sync::StartPassiveSync : syncing",);

                let last = range.start().saturating_sub(1);
                let hash = self
                    .db
                    .get_canonical_block_hash_by_number(last)?
                    .expect("exists");

                self.state = SyncState::Phase4((last, hash));
                self.request_passive_sync()?;
            }
            Ordering::Less => {
                self.prune_range(range)?;
            }
        }
        Ok(())
    }

    /// Utility: Prune blocks
    ///
    /// Deletes both canonical and non-canonical blocks from the DB, given a range.
    pub fn prune_range(&mut self, range: RangeInclusive<u64>) -> Result<()> {
        let prune_ceil = if self.prune_interval != u64::MAX {
            // prune prune-interval
            range.end().saturating_sub(self.prune_interval)
        } else if self.sync_base_height != u64::MAX {
            // prune below sync-base-height
            range
                .end()
                .saturating_sub(MIN_PRUNE_INTERVAL)
                .min(self.sync_base_height.saturating_sub(1))
        } else {
            return Ok(());
        };

        // Prune canonical, and non-canonical blocks.
        tracing::debug!(?range, timeout = %self.prune_timeout_ms, "sync::Prune",);
        let start_now = Instant::now();
        for number in *range.start()..=prune_ceil {
            // check if we have time to prune
            if start_now.elapsed().as_millis() > self.prune_timeout_ms {
                break;
            }
            // remove canonical block and transactions
            if let Some(block) = self.db.get_canonical_block_by_number(number)? {
                tracing::trace!(number = %block.number(), hash=%block.hash(), "sync::Prune");
                self.db.prune_block(&block, true)?;
            }
            // remove any other non-canonical blocks; typically none
            for block in self.db.get_blocks_by_height(number)? {
                tracing::trace!(number = %block.number(), hash=%block.hash(), "sync::Prune");
                self.db.prune_block(&block, false)?;
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
            unimplemented!("sync::RecentBlocks : invalid state");
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
            if self.db.contains_canonical_block(&ancestor_hash)? {
                tracing::info!(?range, "sync::InjectRecent : received");
                self.inject_proposals(proposals)?;
            } else {
                tracing::debug!(?range, "sync::InjectRecent: skipped");
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
        let SyncState::Retry1((range, marker)) = &self.state else {
            unimplemented!("sync::RetryPhase1 : invalid state");
        };

        self.retry_count = self.retry_count.saturating_add(1);
        tracing::debug!(?range, "sync::Retry1 : retrying");

        // Insert faux metadata - we only need the number, parent_hash
        let mut faux_header = BlockHeader::genesis(Hash::ZERO);
        faux_header.number = marker.number.saturating_add(1);
        faux_header.qc.block_hash = marker.hash;

        self.state = SyncState::Phase1(faux_header);
        self.inject_at = None;

        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(())
    }

    /// Handle Passive Sync Request
    pub fn handle_passive_request(
        &mut self,
        from: PeerId,
        request: PassiveSyncRequest,
    ) -> Result<ExternalMessage> {
        tracing::debug!(hash = %request.hash, %from,
            "sync::PassiveRequest : received",
        );

        // Check if we should service this request - https://github.com/Zilliqa/zq2/issues/1878
        if self.is_validator {
            tracing::warn!("sync::PassiveRequest : skip validator");
            return Ok(ExternalMessage::PassiveSyncResponse(vec![]));
        }

        // Do not respond to stale requests as the client has probably timed-out
        if request.request_at.elapsed()?.as_secs() > 20 {
            tracing::warn!("sync::PassiveRequest : stale request");
            return Ok(ExternalMessage::PassiveSyncResponse(vec![]));
        }

        if !self.db.contains_canonical_block(&request.hash)? {
            tracing::warn!("sync::PassiveRequest : block not found");
            return Ok(ExternalMessage::PassiveSyncResponse(vec![]));
        };

        let started_at = Instant::now();
        let mut metas = Vec::new();
        let mut hash = request.hash;
        let mut size = 0;
        // return as much as possible within 1s
        while started_at.elapsed().as_millis() < 1000 {
            // grab the block
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            // and the receipts
            let receipts = self.db.get_transaction_receipts_in_block(&hash)?;
            hash = block.parent_hash();
            // create the response
            let response = PassiveSyncResponse {
                proposal: self.block_to_proposal(block),
                receipts,
            };
            // compute the size
            size += cbor4ii::serde::to_vec(Vec::new(), &response).unwrap().len();
            if size > 9 * 1024 * 1024 {
                break; // too big
            }
            // add to the response
            metas.push(response);
            if metas.len() >= request.count {
                break; // we have enough
            }
        }

        let message = ExternalMessage::PassiveSyncResponse(metas);
        Ok(message)
    }

    /// Phase 4: Handle Passive Header Response
    ///
    pub fn handle_passive_response(
        &mut self,
        from: PeerId,
        response: Option<Vec<PassiveSyncResponse>>,
    ) -> Result<()> {
        let SyncState::Phase4(_) = self.state else {
            tracing::warn!(%from, "sync::PassiveResponse : dropped");
            return Ok(());
        };
        if self.in_flight.is_empty() || self.in_flight.front().unwrap().0.peer_id != from {
            tracing::warn!(%from, "sync::PassiveResponse : spurious");
            return Ok(());
        }

        if let Some(response) = response {
            if !response.is_empty() {
                let range = response.last().unwrap().proposal.number()
                    ..=response.first().unwrap().proposal.number();
                tracing::info!(?range, %from,
                    "sync::PassiveResponse : received",
                );
                self.blocks_downloaded = self.blocks_downloaded.saturating_add(response.len());
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::None);
                // store the blocks in the DB
                self.store_proposals(response)?;
                return Ok(());
            } else {
                tracing::warn!(%from, "sync::PassiveResponse : empty",);
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
            }
        } else {
            tracing::warn!(%from, "sync::PassiveResponse : error",);
            self.peers
                .done_with_peer(self.in_flight.pop_front(), DownGrade::Error);
        }
        // fall-thru in all cases
        self.state = SyncState::Phase0;
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(())
    }

    /// Phase 4: Request Passive Sync
    ///
    /// Request for as much as possible, but will only receive partial response.
    fn request_passive_sync(&mut self) -> Result<()> {
        let SyncState::Phase4((last, hash)) = self.state else {
            unimplemented!("sync::PassiveSync : invalid state");
        };

        // Early exit if there's a request in-flight; and if it has not expired.
        if !self.in_flight.is_empty() {
            tracing::debug!("sync::PassiveSync : syncing");
            return Ok(());
        }

        if let Some(peer_info) = self.peers.get_next_peer() {
            let range = self.sync_base_height..=last;
            tracing::info!(?range, "sync::PassiveSync : requesting");
            let message = ExternalMessage::PassiveSyncRequest(PassiveSyncRequest {
                request_at: SystemTime::now(),
                count: range.count(),
                hash,
            });
            let request_id = self
                .message_sender
                .send_external_message(peer_info.peer_id, message)?;
            self.add_in_flight(peer_info, request_id);
        } else {
            tracing::warn!("sync::PassiveSync : insufficient peers to handle request");
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
        let SyncState::Phase2((_, range, _)) = &self.state else {
            tracing::warn!(%from, "sync::MultiBlockResponse : dropped");
            return Ok(());
        };
        if self.in_flight.is_empty() || self.in_flight.front().unwrap().0.peer_id != from {
            tracing::warn!(%from, "sync::MultiBlockResponse : spurious");
            return Ok(());
        }

        // Only process a full response
        if let Some(response) = response {
            if !response.is_empty() {
                tracing::info!(?range, %from,
                    "sync::MultiBlockResponse : received",
                );
                self.blocks_downloaded = self.blocks_downloaded.saturating_add(response.len());
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::None);
                if self.do_multiblock_response(from, response)? {
                    return Ok(()); // successful 
                };
            } else {
                // Empty response, downgrade peer and retry phase 1.
                tracing::warn!(%from, "sync::MultiBlockResponse : empty",);
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
            }
        } else {
            // Network failure, downgrade peer and retry phase 1.
            tracing::warn!(%from, "sync::MultiBlockResponse : error",);
            self.peers
                .done_with_peer(self.in_flight.pop_front(), DownGrade::Error);
        }
        // failure fall-thru
        if let SyncState::Phase2((_, range, marker)) = &self.state {
            self.state = SyncState::Retry1((range.clone(), *marker));
        };
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(())
    }

    fn do_multiblock_response(&mut self, from: PeerId, response: Vec<Proposal>) -> Result<bool> {
        let check_sum = match &self.state {
            SyncState::Phase2(x) => x.0,
            _ => unimplemented!("sync::MultiBlockResponse : invalid state"),
        };

        // If the checksum does not match, fail.
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
            return Ok(false);
        }

        // Response seems sane.
        let proposals = response
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        // Process the proposals
        if !self.inject_proposals(proposals)? {
            // phase-2 is stuck, cancel sync and restart
            self.state = SyncState::Phase3;
            return Ok(true);
        };

        // if we're done
        if self.segments.count_sync_segments() == 0 {
            self.state = SyncState::Phase3;
        }

        // perform next block transfers, where possible
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(true)
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
        tracing::debug!(length = %request.len(), %from,
            "sync::MultiBlockRequest : received",
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
            unimplemented!("sync::MissingBlocks : invalid state");
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
            if let Some((request_hashes, peer_info, block, range)) =
                self.segments.pop_last_sync_segment()
            {
                // Checksum of the request hashes
                let checksum = request_hashes
                    .iter()
                    .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, h| {
                        sum.with(h.as_bytes())
                    })
                    .finalize();

                // Fire request, to the original peer that sent the segment metadata
                tracing::info!(?range, from = %peer_info.peer_id,
                    "sync::MissingBlocks : requesting",
                );

                self.state = SyncState::Phase2((checksum, range, block));

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
    pub fn handle_active_response(
        &mut self,
        from: PeerId,
        response: Option<Vec<SyncBlockHeader>>,
    ) -> Result<()> {
        if !matches!(self.state, SyncState::Phase1(_)) {
            tracing::warn!(%from, "sync::MetadataResponse : dropped");
            return Ok(());
        };
        if self.in_flight.is_empty() {
            tracing::warn!(%from, "sync::MetadataResponse : spurious");
            return Ok(());
        }

        // buffer response for processing
        self.p1_response.insert(from, response);

        // process responses, in-order
        while let Some((peer, _)) = self.in_flight.front() {
            if self.p1_response.contains_key(&peer.peer_id) {
                let peer_id = peer.peer_id;
                let response = self.p1_response.remove(&peer_id).unwrap();
                if let Some(response) = response {
                    // Only process a full response
                    if response.is_empty() {
                        tracing::warn!("sync::MetadataResponse : empty from {peer_id}");
                        self.peers
                            .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
                    } else {
                        self.headers_downloaded =
                            self.headers_downloaded.saturating_add(response.len());

                        let range = response.last().unwrap().header.number
                            ..=response.first().unwrap().header.number;

                        // full/last segment
                        if response.len() == self.max_batch_size
                            || *range.start() <= self.started_at
                        {
                            tracing::info!(?range, from = %peer_id,
                                "sync::MetadataResponse : received",
                            );
                            let peer = peer.clone();

                            self.peers
                                .done_with_peer(self.in_flight.pop_front(), DownGrade::None);

                            self.do_metadata_response(peer, response)?;
                            continue;
                        } else {
                            // retry partial
                            tracing::warn!("sync::MetadataResponse : partial from {peer_id}");
                            self.peers
                                .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
                        }
                    }
                } else {
                    // Network failure, downgrade peer and retry.
                    tracing::warn!("sync::MetadataResponse : error from {peer_id}");
                    self.peers
                        .done_with_peer(self.in_flight.pop_front(), DownGrade::Error);
                }
                // failure fall-thru - fire one retry
                self.do_missing_metadata(1)?;
                if !self.in_flight.is_empty() {
                    self.in_flight.rotate_right(1); // adjust request order, do_missing_metadata() pushes peer to the back.
                }
            } else {
                break;
            }
        }
        // perform next block transfers, where possible
        if Self::DO_SPECULATIVE {
            self.do_sync()?;
        }
        Ok(())
    }

    fn do_metadata_response(
        &mut self,
        segment_peer: PeerInfo,
        response: Vec<SyncBlockHeader>,
    ) -> Result<()> {
        let meta = match &self.state {
            SyncState::Phase1(meta) => meta,
            _ => unimplemented!("sync::DoMetadataResponse : invalid state"),
        };

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

            // Record segment marker
            self.segments
                .push_sync_segment(&segment_peer, segment.first().unwrap().hash);

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
                // additional segment markers are inserted in descending order
                self.segments.push_sync_segment(&segment_peer, header.hash);
            }

            // Record the oldest block in the segment
            self.state = SyncState::Phase1(segment.last().cloned().unwrap());
            // check if the segment hits our history
            let block_hash = segment.last().as_ref().unwrap().qc.block_hash;
            self.db
                .contains_canonical_block(&block_hash)
                .unwrap_or_default()
        } else {
            true
        };

        // Turnaround to download blocks
        if turnaround {
            self.state = SyncState::Phase2((Hash::ZERO, 0..=0, BlockHeader::genesis(Hash::ZERO)));
            // drop all pending requests & responses
            self.p1_response.clear();
            for p in self.in_flight.drain(..) {
                self.peers.done_with_peer(Some(p), DownGrade::None);
            }
        }
        Ok(())
    }

    /// Returns the metadata of the chain from a given hash.
    ///
    /// This constructs a historical chain going backwards from a hash, by following the parent_hash.
    /// It collects N blocks and returns the metadata of that particular chain.
    /// This is mainly used in Phase 1 of the syncing algorithm, to construct a chain history.
    pub fn handle_active_request(
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
            return Ok(ExternalMessage::SyncBlockHeaders(vec![]));
        }

        let batch_size = Self::MAX_BATCH_SIZE
            .min(request.to_height.saturating_sub(request.from_height) as usize);
        let mut metas = Vec::with_capacity(batch_size);
        let Some(block) = self.db.get_canonical_block_by_number(request.to_height)? else {
            tracing::warn!("sync::MetadataRequest : block not found");
            return Ok(ExternalMessage::SyncBlockHeaders(vec![]));
        };

        let mut hash = block.hash();
        while metas.len() <= batch_size {
            // grab the parent
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            hash = block.parent_hash();

            // Size cache is needed.
            // Otherwise, a large block can cause a node to get stuck syncing since no node can respond to the request in time.
            let encoded_size = self.size_cache.get(&hash).cloned().unwrap_or_else(|| {
                // pseudo-LRU approximation
                if self.size_cache.len() > Self::MAX_CACHE_SIZE {
                    let mut rng = rand::thread_rng();
                    self.size_cache.retain(|_, _| rng.gen_bool(0.9));
                }

                let proposal = self.block_to_proposal(block.clone());
                let encoded_size = cbor4ii::serde::to_vec(Vec::new(), &proposal).unwrap().len();
                self.size_cache.insert(hash, encoded_size);
                encoded_size
            });

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
    pub fn request_missing_headers(&mut self) -> Result<()> {
        if !matches!(self.state, SyncState::Phase1(_)) {
            unimplemented!("sync::RequestMissingHeaders : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if !self.in_flight.is_empty() || self.in_pipeline > self.max_batch_size {
            // anything more than this and we cannot be sure whether the segment hits history
            tracing::debug!(
                "sync::RequestMissingHeaders : syncing {}/{} blocks",
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
            tracing::warn!("sync::RequestMissingHeaders : no peers to handle request");
            return Ok(());
        }

        self.do_missing_metadata(peer_set)
    }

    /// Phase 1: Request chain metadata from a peer.
    ///
    /// This fires concurrent requests to N peers, to fetch different segments of chain metadata.
    /// The number of requests is limited by:
    /// - the number of good peers
    /// - hitting the starting point
    /// - encountering a V1 peer
    fn do_missing_metadata(&mut self, num_peers: usize) -> Result<()> {
        if !matches!(self.state, SyncState::Phase1(_)) {
            unimplemented!("sync::DoMissingMetadata : invalid state");
        }
        let mut offset = u64::MIN;
        for num in 1..=num_peers {
            if let Some(peer_info) = self.peers.get_next_peer() {
                let (message, done, range) = match &self.state {
                    SyncState::Phase1(BlockHeader {
                        number: block_number,
                        ..
                    }) => {
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
                    _ => unreachable!(),
                };

                tracing::info!(?range, from = %peer_info.peer_id,
                    "sync::DoMissingMetadata : requesting ({num}/{num_peers})",
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

    /// Phase 5: Store Proposals
    ///
    /// These need only be stored, not executed - IN DESCENDING ORDER.
    fn store_proposals(&mut self, response: Vec<PassiveSyncResponse>) -> Result<()> {
        let SyncState::Phase4((mut number, mut hash)) = self.state else {
            unimplemented!("sync::StoreProposals : invalid state");
        };
        let response = response
            .into_iter()
            .sorted_by_key(|p| Reverse(p.proposal.number()))
            .collect_vec();
        if !response.is_empty() {
            // Store it from high to low
            for PassiveSyncResponse { proposal, receipts } in response {
                // Check for correct order
                if number == proposal.number() && hash == proposal.hash() {
                    number = number.saturating_sub(1);
                    hash = proposal.header.qc.block_hash;
                } else {
                    tracing::error!(
                        "sync::StoreProposals : unexpected proposal number={number} != {}; hash={hash} != {}",
                        proposal.number(),
                        proposal.hash(),
                    );
                    return Ok(());
                }

                // All OK - Store it
                tracing::trace!(
                    number = %proposal.number(), hash = %proposal.hash(),
                    "sync::StoreProposals : applying",
                );
                let (block, transactions) = proposal.into_parts();
                self.db.with_sqlite_tx(|sqlite_tx| {
                    // Insert transactions
                    for t in transactions {
                        let hash = t.calculate_hash();
                        self.db
                            .insert_transaction_with_db_tx(sqlite_tx, &hash, &t)?;
                    }
                    // Insert block
                    self.db.insert_block_with_db_tx(sqlite_tx, &block)?;
                    // Insert receipts
                    for r in receipts {
                        self.db
                            .insert_transaction_receipt_with_db_tx(sqlite_tx, r)?;
                    }
                    Ok(())
                })?;
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
        let sync_phases = matches!(
            self.state,
            SyncState::Phase1(_) | SyncState::Phase2(_) | SyncState::Phase3 | SyncState::Retry1(_)
        );
        Ok(sync_phases || self.in_pipeline != 0)
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
                passive_sync_count: self.passive_sync_count,
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
    Phase2((Hash, RangeInclusive<u64>, BlockHeader)),
    Phase3,
    Retry1((RangeInclusive<u64>, BlockHeader)),
    Phase4((u64, Hash)),
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncState::Phase0 => write!(f, "phase0"),
            SyncState::Phase1(_) => write!(f, "phase1"),
            SyncState::Phase2(_) => write!(f, "phase2"),
            SyncState::Phase3 => write!(f, "phase3"),
            SyncState::Retry1(_) => write!(f, "retry1"),
            SyncState::Phase4(_) => write!(f, "phase4"),
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
    V1 = 1, // deprecated
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
    markers: VecDeque<(Hash, PeerInfo)>,
}

impl SyncSegments {
    /// Returns the number of stored sync segments
    fn count_sync_segments(&self) -> usize {
        self.markers.len()
    }

    /// Pop the stack, for active-sync from marker (inclusive)
    fn pop_last_sync_segment(
        &mut self,
    ) -> Option<(Vec<Hash>, PeerInfo, BlockHeader, RangeInclusive<u64>)> {
        let (mut hash, mut peer) = self.markers.pop_back()?;
        let mut hashes = vec![];
        let high_at = self.headers.get(&hash)?.number;
        let high_hash = self.headers.get(&hash)?.hash;
        let mut low_at = 0;
        while let Some(header) = self.headers.remove(&hash) {
            low_at = header.number;
            hashes.push(header.hash);
            hash = header.qc.block_hash;
        }
        peer.last_used = Instant::now();
        peer.score = u32::MAX;

        let mut faux_marker = BlockHeader::genesis(Hash::ZERO);
        faux_marker.number = high_at;
        faux_marker.hash = high_hash;

        Some((hashes, peer, faux_marker, low_at..=high_at))
    }

    /// Pushes a particular segment into the stack/queue.
    fn push_sync_segment(&mut self, peer: &PeerInfo, hash: Hash) {
        // do not double-push
        let last = self.markers.back().map_or_else(|| Hash::ZERO, |(h, _)| *h);
        if hash != last {
            self.markers.push_back((hash, peer.clone()));
        }
    }

    /// Bulk inserts a bunch of metadata.
    fn insert_sync_metadata(&mut self, metas: &Vec<BlockHeader>) {
        for meta in metas {
            self.headers.insert(meta.hash, *meta);
        }
    }

    /// Empty the metadata table.
    fn empty_sync_metadata(&mut self) {
        self.markers.clear();
        self.headers.clear();
    }
}

// FIXME: Find a better way to do this, other than checking for debug/release build.
// For the purpose of testing, we need a smaller prune interval to ensure that the test cases run faster.
#[cfg(debug_assertions)]
pub const MIN_PRUNE_INTERVAL: u64 = 10;
#[cfg(not(debug_assertions))]
pub const MIN_PRUNE_INTERVAL: u64 = 300;
