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
use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use tracing::{debug, error, info, trace, warn};

use crate::{
    api::types::eth::{SyncingMeta, SyncingStruct},
    cfg::NodeConfig,
    crypto::Hash,
    data_access,
    db::{BlockFilter, Db},
    message::{
        Block, BlockHeader, BlockRequest, BlockResponse, BlockTransactionsReceipts,
        ExternalMessage, InjectedProposal, Proposal, RequestBlocksByHash, RequestBlocksByHeight,
        SyncBlockHeader,
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
|  | PHASE-4: PASSIVE BLOCKS    |    | PHASE-1: ACTIVE HEADERS    |                                  |
|  |                            |    |                            <----------------+                 |
|  | Request missing blocks.    |    | Request missing headers.   |                |                 |
|  +-+--------------------------+    +--+-------------------------+                |                 |
|    |                                  |                                          |                 |
|    | Receive & store blocks.          | Received headers hits our history.       |                 |
|    |                                  |                                          |                 |
+----+                               +--v-------------------------+             +--+--------------+  |
                                     | PHASE-2: ACTIVE BLOCKS     |             | RETRY-1: RETRY  |  |
                                     |                            |  on errors  |                 |  |
                                     | Request missing blocks.    +-------------> Retry 1-segment |  |
                                     +--+-------------------------+             +-----------------+  |
                                        |                                                            |
                                        | Receive all requested blocks.                              |
                                        |                                                            |
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
// PHASE4: Request blocks
// Request as many archival blocks as possible.
// 1. We start with the lowest block in our chain, and request blocks from down to `base_height`
// 2. We store the blocks from the received response.
// 3. We unconditionally move to Phase 0, to wait for the next Proposal.

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
    // how many blocks to inject into the queue
    max_blocks_in_flight: usize,
    max_idle_duration: Duration,
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
    size_cache: HashMap<Hash, usize>,
    // passive sync
    sync_base_height: u64,
    zq2_floor_height: u64,
    ignore_passive: bool,
    // periodic vacuum
    vacuum_at: u64,
    // checkpoint period
    checkpoint_period: u64,
}

impl Sync {
    // Speed up by fetching multiple segments in Phase 1.
    const MAX_CONCURRENT_PEERS: usize = 10;
    // Mitigate DoS
    const MAX_BATCH_SIZE: usize = 100;
    // Cache recent block sizes
    const MAX_CACHE_SIZE: usize = 100_000;
    // Do not overflow libp2p::request-response::cbor::codec::RESPONSE_SIZE_MAXIMUM = 10MB (default)
    const RESPONSE_SIZE_THRESHOLD: usize = crate::constants::SYNC_THRESHOLD;
    // periodic vacuum interval
    const VACUUM_INTERVAL: u64 = 604800; // 'weekly'

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
            .clamp(10, Self::MAX_BATCH_SIZE); // reduce the max batch size - 100 is more than sufficient; less may work too.
        let max_blocks_in_flight = config.sync.max_blocks_in_flight.clamp(
            max_batch_size,
            Self::MAX_BATCH_SIZE * Self::MAX_CONCURRENT_PEERS, // phase 2 buffering - 1000 is more than sufficient; more may work too.
        );
        let sync_base_height = config.sync.base_height;
        let prune_interval = config.sync.prune_interval;
        // Start from reset, or continue sync
        let latest_block_number = latest_block
            .as_ref()
            .map_or_else(|| u64::MIN, |b| b.number());

        // If set, sync_base_height must be sane
        if sync_base_height != u64::MAX && latest_block_number < sync_base_height {
            return Err(anyhow::anyhow!("sync_base_height > highest_block"));
        }

        let zq2_floor_height = config
            .consensus
            .get_forks()?
            .find_height_fork_first_activated(crate::cfg::ForkName::ExecutableBlocks)
            .unwrap_or_default();

        let ignore_passive = config.sync.ignore_passive; // defaults to servicing passive-sync requests

        if latest_block_number < zq2_floor_height {
            return Err(anyhow::anyhow!("Please restore from a checkpoint"));
        }

        // at some random point in the future, or never
        let vacuum_at = if prune_interval != u64::MAX {
            latest_block_number
                .saturating_add(rand::thread_rng().gen_range(1..Self::VACUUM_INTERVAL))
        } else {
            u64::MAX
        };

        // Idle duration
        let max_idle_duration = config.consensus.block_time / 3;

        // checkpoint period
        let checkpoint_period =
            config.consensus.epochs_per_checkpoint * config.consensus.blocks_per_epoch;

        Ok(Self {
            db,
            message_sender,
            peer_id,
            peers,
            max_batch_size,
            max_blocks_in_flight,
            max_idle_duration,
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
            segments: SyncSegments::new(),
            cache_probe_response: None,
            last_probe_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(), // allow immediate sync at startup
            sync_base_height,
            prune_interval,
            size_cache: HashMap::with_capacity(Self::MAX_CACHE_SIZE),
            zq2_floor_height,
            ignore_passive,
            vacuum_at,
            checkpoint_period,
        })
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
        if self
            .in_flight
            .iter()
            .any(|(p, r)| p.peer_id == failure.peer && *r == failure.request_id)
        {
            warn!(peer = %failure.peer, err=%failure.error, "RequestFailure : failed");
            match &self.state {
                SyncState::Phase1(_) => self.handle_active_response(failure.peer, None)?,
                SyncState::Phase2(_) => self.handle_multiblock_response(failure.peer, None)?,
                SyncState::Phase4(_) => self.handle_passive_response(failure.peer, None)?,
                state => error!(%state, %from, "RequestFailure : invalid"),
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
            debug!("SyncFromProbe : syncing");
            return Ok(());
        }
        // avoid spamming the network
        let elapsed = self.last_probe_at.elapsed().as_secs();
        if elapsed < 60 {
            debug!(?elapsed, "SyncFromProbe : skipping");
            return Ok(());
        } else {
            self.last_probe_at = Instant::now();
        }
        // inevitably picks a bootstrap node
        if let Some(peer_info) = self.peers.get_next_peer() {
            let peer = peer_info.peer_id;
            self.peers.append_peer(peer_info);
            info!(%peer, "SyncFromProbe : probing");
            self.probe_peer(peer);
        } else {
            warn!("SyncFromProbe: insufficient peers");
        }
        Ok(())
    }

    /// Drive the sync state-machine.
    fn do_sync(&mut self) -> Result<()> {
        if self.recent_proposals.is_empty() {
            // Do nothing if there's no recent proposals.
            debug!("DoSync : missing recent proposals");
            return Ok(());
        }

        // check in-flights; manually failing one stale request at a time
        if let Some((
            PeerInfo {
                peer_id, last_used, ..
            },
            request_id,
        )) = self.in_flight.front()
        {
            if last_used.elapsed().as_secs() > 90 {
                warn!(%peer_id, ?request_id, "DoSync : stale");
                self.handle_request_failure(
                    self.peer_id, // self-triggered
                    OutgoingMessageFailure {
                        peer: *peer_id,
                        request_id: *request_id,
                        error: libp2p::autonat::OutboundFailure::Timeout,
                    },
                )?;
            }
            return Ok(());
        }

        trace!(state = %self.state, "DoSync");

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
            SyncState::Phase2(_) if self.in_pipeline < self.max_batch_size => {
                self.request_missing_blocks()?;
            }
            // Wait till 99% synced, zip it up!
            SyncState::Phase3 if self.in_pipeline == 0 => {
                self.inject_recent_blocks()?;
            }
            // Retry to fix sync issues e.g. peers that are now offline
            SyncState::Retry1(_) if self.in_pipeline == 0 => {
                self.retry_phase1()?;
            }
            SyncState::Phase4((last, _)) => {
                let range = self.sync_base_height..=last;
                self.request_passive_sync(range)?;
            }
            _ => {
                debug!(in_pipeline = %self.in_pipeline, "DoSync : syncing");
            }
        }
        Ok(())
    }

    /// Phase 0: Start Active Sync
    ///
    /// Given a block header, start the active sync process from that point going backwards.
    fn start_active_sync(&mut self, meta: BlockHeader) -> Result<()> {
        if !matches!(self.state, SyncState::Phase0) {
            unimplemented!("StartActiveSync : invalid state");
        }
        // No parent block, trigger active-sync
        self.active_sync_count = self.active_sync_count.saturating_add(1);
        debug!(from_hash = %meta.qc.block_hash, "StartActiveSync : syncing",);
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
            unimplemented!("StartPassiveSync : invalid state");
        }

        if self.sync_base_height == u64::MAX && self.prune_interval == u64::MAX {
            return Ok(());
        }

        let range = self.db.available_range()?;

        match (*range.start()).cmp(&self.sync_base_height) {
            Ordering::Equal => {
                self.recover_checkpoints(range)?;
            }
            // passive-sync above sync-base-height
            Ordering::Greater => {
                debug!(?range, "StartPassiveSync : syncing",);

                // start syncing from either the lowest block, or the one below it.
                let bnr = self
                    .db
                    .get_block_and_receipts(BlockFilter::Height(*range.start()))?
                    .expect("must exist");

                let (last, hash) =
                    // if the block is supposed to have txns/receipts, but none are in the DB
                    if bnr.receipts.is_empty() && bnr.block.receipts_root_hash() != Hash::EMPTY {
                        // the block txn/receipts are missing; needs to be re-synced e.g. checkpoint parent
                        (bnr.block.number(), bnr.block.hash())
                    } else {
                        // sync the block below the lowest known block
                        (
                            bnr.block.number().saturating_sub(1),
                            bnr.block.parent_hash(),
                        )
                    };

                self.state = SyncState::Phase4((last, hash));
                let range = self.sync_base_height..=last;
                self.request_passive_sync(range)?;
            }
            Ordering::Less => {
                let last_prune = self.prune_range(range)?;
                if last_prune > self.vacuum_at {
                    tracing::info!("Vacuum at {last_prune} then {}", self.vacuum_at);
                    self.db.vacuum()?;
                    self.vacuum_at = last_prune.saturating_add(Self::VACUUM_INTERVAL);
                }
            }
        }
        Ok(())
    }

    /// Recovers missing checkpoint parent block (if any).
    /// In the case of nodes that have already been passive-synced, past non-empty parent blocks.
    fn recover_checkpoints(&mut self, range: RangeInclusive<u64>) -> Result<()> {
        let start = range.start().saturating_div(self.checkpoint_period);
        let end = range.end().saturating_div(self.checkpoint_period);

        for n in start..=end {
            let num = n.saturating_mul(self.checkpoint_period).saturating_sub(1); // calculate checkpoint parent
            let Some(bnr) = self.db.get_block_and_receipts(BlockFilter::Height(num))? else {
                continue; // skip if block not found
            };
            if !bnr.receipts.is_empty() || bnr.block.receipts_root_hash() == Hash::EMPTY {
                continue; // skip if block has empty transactions root hash
            }
            let block = bnr.block;
            tracing::info!(number=%block.number(), hash=%block.hash(), "Recovering checkpoint");
            self.state = SyncState::Phase4((block.number(), block.hash()));
            let range = block.number()..=block.number();
            return self.request_passive_sync(range); // request 1 block only
        }
        self.sync_base_height = u64::MAX; // no more to process
        Ok(())
    }

    /// Utility: Prune blocks
    ///
    /// Deletes both canonical and non-canonical blocks from the DB, given a range.
    /// Returns the highest block number pruned
    pub fn prune_range(&mut self, range: RangeInclusive<u64>) -> Result<u64> {
        let prune_ceil = if self.prune_interval != u64::MAX {
            // prune prune-interval
            range
                .end()
                .saturating_sub(self.prune_interval.saturating_sub(1))
        } else if self.sync_base_height != u64::MAX {
            // prune below sync-base-height
            range
                .end()
                .saturating_sub(MIN_PRUNE_INTERVAL.saturating_sub(1))
                .min(self.sync_base_height)
        } else {
            return Ok(u64::MIN);
        };

        // Prune canonical, and non-canonical blocks.
        debug!(?range, "Prune",);
        let start_now = Instant::now();
        for number in *range.start()..prune_ceil {
            // check if we have time to prune
            if start_now.elapsed() > self.max_idle_duration {
                return Ok(number);
            }
            // remove canonical block and transactions
            if let Some(block) = self.db.get_block(BlockFilter::Height(number))? {
                trace!(number = %block.number(), hash=%block.hash(), "Prune");
                self.db.prune_block(&block, true)?;
            }
            // remove any other non-canonical blocks; typically none
            for block in self.db.get_blocks_by_height(number)? {
                trace!(number = %block.number(), hash=%block.hash(), "Prune");
                self.db.prune_block(&block, false)?;
            }
        }
        Ok(prune_ceil)
    }

    /// Injects the recent proposals
    ///
    /// The recent proposals have been buffering while active-sync is in process to 99%.
    /// This injects the last 1% to finish it up.
    fn inject_recent_blocks(&mut self) -> Result<()> {
        if !matches!(self.state, SyncState::Phase3) {
            unimplemented!("RecentBlocks : invalid state");
        }
        // Only inject recent proposals - https://github.com/Zilliqa/zq2/issues/2520
        let highest_block = self
            .db
            .get_block(BlockFilter::MaxHeight)?
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
                info!(?range, "InjectRecent : received");
                self.inject_proposals(proposals)?;
            } else {
                debug!(?range, "InjectRecent: skipped");
            }
        }
        self.segments.empty_sync_metadata()?;
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
        if self.started_at < self.zq2_floor_height {
            error!(
                "Starting block {} is below ZQ2 height {}",
                self.started_at, self.zq2_floor_height
            );
        }
        Ok(())
    }

    /// Convenience function to convert a block to a proposal (add full txs)
    /// Should only be used for syncing history, not for consensus messages regarding new blocks.
    fn brt_to_proposal(&self, brt: crate::db::BlockAndReceiptsAndTransactions) -> Proposal {
        let block = brt.block;
        // since block must be valid, unwrap(s) are safe
        let txs = brt
            .transactions
            .into_iter()
            // handle verification on the client-side
            .map(|tx| (tx.tx, tx.hash))
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
            unimplemented!("RetryPhase1 : invalid state");
        };

        self.retry_count = self.retry_count.saturating_add(1);
        debug!(?range, "Retry1");

        // Insert faux metadata - we only need the number, parent_hash
        let mut faux_header = BlockHeader::genesis(Hash::ZERO);
        faux_header.number = marker.number.saturating_add(1);
        faux_header.qc.block_hash = marker.hash;

        self.state = SyncState::Phase1(faux_header);
        self.inject_at = None;

        // Ensure started is updated - https://github.com/Zilliqa/zq2/issues/2306
        self.update_started_at()?;
        self.do_sync()
    }

    /// Handle Passive Sync Request
    pub fn handle_passive_request(
        &mut self,
        from: PeerId,
        request: RequestBlocksByHash,
    ) -> Result<ExternalMessage> {
        debug!(hash = %request.hash, count = %request.count, %from,
            "PassiveRequest : received",
        );

        // Check if we should service this request - https://github.com/Zilliqa/zq2/issues/1878
        if self.ignore_passive {
            warn!("PassiveRequest : ignored");
            return Ok(ExternalMessage::PassiveSyncResponse(vec![]));
        }

        // Do not respond to stale requests as the client has probably timed-out
        if request.request_at.elapsed()?.as_secs() > 20 {
            warn!("PassiveRequest : stale");
            return Ok(ExternalMessage::PassiveSyncResponse(vec![]));
        }

        if !self.db.contains_canonical_block(&request.hash)? {
            warn!("PassiveRequest : missing");
            return Ok(ExternalMessage::PassiveSyncResponse(vec![]));
        };

        let started_at = Instant::now();
        let mut metas = Vec::new();
        let mut hash = request.hash;
        let mut size = 0;
        // return as much as possible within idle time
        while started_at.elapsed() < self.max_idle_duration {
            let Some(brt) = self
                .db
                .get_block_and_receipts_and_transactions(hash.into())?
            else {
                break;
            };
            let block = brt.block;
            let number = block.number();
            let receipts = brt.receipts;

            // TODO: transactions are receipts are already sorted, just zip them together
            let transactions: HashMap<Hash, crate::transaction::SignedTransaction> = brt
                .transactions
                .into_iter()
                .map(|tx| (tx.hash, tx.tx))
                .collect();

            let transaction_receipts = receipts
                .into_iter()
                .map(|r| {
                    let txn = transactions.get(&r.tx_hash).unwrap();
                    (txn.clone(), r)
                })
                .collect_vec();
            hash = block.parent_hash();

            // create the response
            let response = BlockTransactionsReceipts {
                block,
                transaction_receipts,
            };

            // compute the size
            let encoded = cbor4ii::serde::to_vec(Vec::new(), &response)?;
            size += encoded.len();
            if size > Self::RESPONSE_SIZE_THRESHOLD {
                // if the block is big, we will skip it for the current set of responses; and
                // it will go into the next response as a compressed block
                if !metas.is_empty() {
                    break; // return whatever fits
                }

                warn!(%number, %size, "PassiveRequest : exceeded");
                // compress the single block; and respond
                let mut encoder = lz4::EncoderBuilder::new().build(Vec::new())?;
                std::io::Write::write_all(&mut encoder, &encoded)?;
                let (lzblock, result) = encoder.finish();
                result.expect("PassiveRequest : lz4");
                return Ok(ExternalMessage::PassiveSyncResponseLZ(lzblock));
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
        response: Option<Vec<BlockTransactionsReceipts>>,
    ) -> Result<()> {
        let SyncState::Phase4(_) = self.state else {
            warn!(%from, "PassiveResponse : dropped");
            return Ok(());
        };
        if self.in_flight.is_empty() || self.in_flight.front().unwrap().0.peer_id != from {
            warn!(%from, "PassiveResponse : spurious");
            return Ok(());
        }

        if let Some(response) = response {
            if !response.is_empty() {
                info!(length = response.len(), %from,
                    "PassiveResponse : received",
                );
                // self.blocks_downloaded = self.blocks_downloaded.saturating_add(response.len());
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::None);

                // store the blocks in the DB
                self.store_proposals(response)?;
            } else {
                warn!(%from, "PassiveResponse : empty",);
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
            }
        } else {
            warn!(%from, "PassiveResponse : error",);
            self.peers
                .done_with_peer(self.in_flight.pop_front(), DownGrade::Error);
        }
        // fall-thru in all cases
        self.state = SyncState::Phase0;
        self.do_sync()
    }

    /// Phase 4: Request Passive Sync
    ///
    /// Request for as much as possible, but will only receive partial response.
    fn request_passive_sync(&mut self, range: RangeInclusive<u64>) -> Result<()> {
        let SyncState::Phase4((_last, hash)) = self.state else {
            unimplemented!("PassiveSync : invalid state");
        };

        // Early exit if there's a request in-flight; and if it has not expired.
        if !self.in_flight.is_empty() {
            debug!("PassiveSync : syncing");
            return Ok(());
        }

        if let Some(peer_info) = self.peers.get_next_peer() {
            info!(?range, from = %peer_info.peer_id, "PassiveSync : requesting");
            let message = ExternalMessage::PassiveSyncRequest(RequestBlocksByHash {
                request_at: SystemTime::now(),
                count: range.count(),
                hash,
            });
            let request_id = self
                .message_sender
                .send_external_message(peer_info.peer_id, message)?;
            self.add_in_flight(peer_info, request_id);
        } else {
            warn!("PassiveSync : insufficient peers");
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
            warn!(%from, "MultiBlockResponse : dropped");
            return Ok(());
        };
        if self.in_flight.is_empty() || self.in_flight.front().unwrap().0.peer_id != from {
            warn!(%from, "MultiBlockResponse : spurious");
            return Ok(());
        }

        // Only process a full response
        if let Some(response) = response {
            if !response.is_empty() {
                info!(?range, %from,
                    "MultiBlockResponse : received",
                );
                self.blocks_downloaded = self.blocks_downloaded.saturating_add(response.len());
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::None);
                if self.do_multiblock_response(from, response)? {
                    return Ok(()); // successful
                };
            } else {
                // Empty response, downgrade peer and retry phase 1.
                warn!(%from, "MultiBlockResponse : empty",);
                self.peers
                    .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
            }
        } else {
            // Network failure, downgrade peer and retry phase 1.
            warn!(%from, "MultiBlockResponse : error",);
            self.peers
                .done_with_peer(self.in_flight.pop_front(), DownGrade::Error);
        }
        // failure fall-thru
        if let SyncState::Phase2((_, range, marker)) = &self.state {
            self.state = SyncState::Retry1((range.clone(), *marker));
        };
        self.do_sync()
    }

    fn do_multiblock_response(&mut self, from: PeerId, response: Vec<Proposal>) -> Result<bool> {
        let check_sum = match &self.state {
            SyncState::Phase2(x) => x.0,
            _ => unimplemented!("MultiBlockResponse : invalid state"),
        };

        // If the checksum does not match, fail.
        let computed_sum = response
            .iter()
            .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, p| {
                sum.with(p.hash().as_bytes())
            })
            .finalize();

        if check_sum != computed_sum {
            error!(
                "MultiBlockResponse : unexpected checksum={check_sum} != {computed_sum} from {from}"
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
        };

        // if we're done
        if self.segments.count_sync_segments()? == 0 {
            self.state = SyncState::Phase3;
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
        debug!(length = %request.len(), %from,
            "MultiBlockRequest : received",
        );

        // TODO: Any additional checks
        // Validators should not respond to this, unless they are free e.g. stuck in an exponential backoff.

        let batch_size: usize = Self::MAX_BATCH_SIZE.min(request.len()); // mitigate DOS by limiting the number of blocks we return
        let mut proposals = Vec::with_capacity(batch_size);
        let mut cbor_size = 0;
        for hash in request {
            if cbor_size > Self::RESPONSE_SIZE_THRESHOLD {
                break; // response size limit reached
            }
            let Some(brt) = self
                .db
                .get_block_and_receipts_and_transactions(hash.into())?
            else {
                break;
            };

            if brt.block.number() < self.zq2_floor_height {
                // do not active sync ZQ1 blocks
                warn!("MultiBlockRequest : skipping ZQ1");
                break;
            }

            let proposal = self.brt_to_proposal(brt);
            let encoded_size = self.size_cache.get(&hash).cloned().unwrap_or_else(|| {
                cbor4ii::serde::to_vec(Vec::with_capacity(1024 * 1024), &proposal)
                    .unwrap()
                    .len()
            });
            cbor_size = cbor_size.saturating_add(encoded_size);
            proposals.push(proposal);
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
            unimplemented!("MissingBlocks : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if !self.in_flight.is_empty() || self.in_pipeline > self.max_blocks_in_flight {
            debug!(
                "MissingBlocks : syncing {}/{} blocks",
                self.in_pipeline, self.max_blocks_in_flight
            );
            return Ok(());
        }

        // will be re-inserted below
        if let Some(peer) = self.peers.get_next_peer() {
            // reinsert peer, as we will use a faux peer below, to force the request to go to the original responder
            self.peers.reinsert_peer(peer);

            // If we have no chain_segments, we have nothing to do
            if let Some((request_hashes, peer_info, block, range)) =
                self.segments.pop_last_sync_segment()?
            {
                // Checksum of the request hashes
                let checksum = request_hashes
                    .iter()
                    .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, h| {
                        sum.with(h.as_bytes())
                    })
                    .finalize();

                // Fire request, to the original peer that sent the segment metadata
                info!(?range, from = %peer_info.peer_id,
                    "MissingBlocks : requesting",
                );

                self.state = SyncState::Phase2((checksum, range, block));

                let message = ExternalMessage::MultiBlockRequest(request_hashes);
                let request_id = self
                    .message_sender
                    .send_external_message(peer_info.peer_id, message)?;
                self.add_in_flight(peer_info, request_id);
            } else {
                warn!("MissingBlocks : no segments");
                self.state = SyncState::Phase3;
            }
        } else {
            warn!("MissingBlocks : insufficient peers");
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
                    debug!(self = %self.started_at, block = %proposal.number(), %from,
                        "BlockResponse : syncing",
                    );
                    self.sync_from_proposal(proposal)?;
                } else {
                    debug!(self = %self.started_at, block = %proposal.number(), %from,
                        "BlockResponse : skipped",
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
        let brt = self
            .db
            .get_block_and_receipts_and_transactions(BlockFilter::MaxCanonicalByHeight)?
            .unwrap();

        info!(%from, number = %brt.block.number(), "BlockRequest : received");

        // send cached response
        if let Some(prop) = self.cache_probe_response.as_ref()
            && prop.hash() == brt.block.hash()
        {
            return Ok(ExternalMessage::BlockResponse(BlockResponse {
                proposals: vec![prop.clone()],
                from_view: u64::MAX,
                availability: None,
            }));
        };

        // Construct the proposal
        let prop = self.brt_to_proposal(brt);
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
            warn!(%from, "ActiveResponse : dropped");
            return Ok(());
        };
        if self.in_flight.is_empty() {
            warn!(%from, "ActiveResponse : spurious");
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
                    if response.is_empty() || response.len() > self.max_batch_size {
                        warn!(from = %peer_id, "ActiveResponse : invalid");
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
                            info!(?range, from = %peer_id,
                                "ActiveResponse : received",
                            );
                            let peer = peer.clone();

                            self.peers
                                .done_with_peer(self.in_flight.pop_front(), DownGrade::None);

                            self.do_metadata_response(peer, response)?;
                            continue;
                        } else {
                            // retry partial
                            warn!(from = %peer_id, "ActiveResponse : partial");
                            self.peers
                                .done_with_peer(self.in_flight.pop_front(), DownGrade::Empty);
                        }
                    }
                } else {
                    // Network failure, downgrade peer and retry.
                    warn!(from = %peer_id, "ActiveResponse : error");
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

        // Stop potential recursion issues - https://github.com/Zilliqa/zq2/issues/3006
        // Only progress the state machine when all the pending requests are completed, either way.
        if !self.in_flight.is_empty() {
            return Ok(());
        }
        self.do_sync()
    }

    fn do_metadata_response(
        &mut self,
        segment_peer: PeerInfo,
        response: Vec<SyncBlockHeader>,
    ) -> Result<()> {
        let meta = match &self.state {
            SyncState::Phase1(meta) => meta,
            _ => unimplemented!("DoMetadataResponse : invalid state"),
        };

        // Check the linkage of the returned chain
        let mut block_hash = meta.qc.block_hash;
        let mut block_num = meta.number;
        for SyncBlockHeader { header: meta, .. } in response.iter() {
            info!("RECEIVED meta block num: {}, view: {}, hash: {:?}. BLock num: {}, block_hash: {:?}", meta.number, meta.view, meta.hash, block_num, block_hash);
            // check that the block hash and number is as expected.
            if meta.hash != Hash::ZERO && block_hash == meta.hash && block_num == meta.number + 1 {
                block_hash = meta.qc.block_hash;
                block_num = meta.number;
            } else {
                // If something does not match, restart from the last known segment.
                // This is a safety mechanism to prevent a peer from sending us garbage.
                error!(
                    "DoMetadataResponse : unexpected metadata hash={block_hash} != {}, num={block_num} != {}",
                    meta.hash, meta.number,
                );
                // Unless, it is the first segment, where it will restart the entire sync.
                // https://github.com/Zilliqa/zq2/issues/2416
                if self.segments.count_sync_segments()? <= 1 {
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
        let segment = response
            .into_iter()
            .filter(|b| {
                trace!(size = %b.size_estimate, number = %b.header.number, "DoMetadataResponse : block");
                drop |= self
                    .db
                    .contains_canonical_block(&b.header.hash)
                    .unwrap_or_default();
                !drop
            })
            .collect_vec();

        // Record non-empty segment
        if !segment.is_empty() {
            // Record segment landmark/marker
            self.segments
                .push_sync_segment(&segment_peer, segment.first().unwrap().header.hash)?;
            let segment_last = segment.last().cloned().unwrap().header;

            // Dynamic sub-segments - https://github.com/Zilliqa/zq2/issues/2312
            let mut block_size: usize = 0;
            let mut sub_segments = segment
                .into_iter()
                .rev() // Computed in ascending order, so that landmarks always top the segment.
                .filter(|&sb| {
                    self.segments.insert_sync_metadata(&sb.header).unwrap(); // record all metadata
                    block_size = block_size.saturating_add(sb.size_estimate);
                    trace!(total=%block_size, "DoMetadataResponse : response");
                    if block_size > Self::RESPONSE_SIZE_THRESHOLD {
                        block_size = 0;
                        true
                    } else {
                        false
                    }
                })
                .collect_vec();
            while let Some(SyncBlockHeader { header, .. }) = sub_segments.pop() {
                // segment markers are inserted in descending order, which is the order in the stack.
                self.segments
                    .push_sync_segment(&segment_peer, header.hash)?;
            }

            // Record the oldest block in the segment
            self.state = SyncState::Phase1(segment_last);
        }

        if drop {
            // turnaround to Phase 2.
            self.state = SyncState::Phase2((Hash::ZERO, 0..=0, BlockHeader::genesis(Hash::ZERO)));
            // drop all pending requests & responses
            self.p1_response.clear();
            for p in self.in_flight.drain(..) {
                self.peers.done_with_peer(Some(p), DownGrade::None);
            }
            self.segments.flush()?;
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
        debug!(?range, %from,
            "MetadataRequest : received",
        );

        if self.zq2_floor_height > request.to_height {
            warn!("MetadataRequest : skipping ZQ1");
            return Ok(ExternalMessage::SyncBlockHeaders(vec![]));
        }

        // Do not respond to stale requests as the client has probably timed-out
        if request.request_at.elapsed()?.as_secs() > 20 {
            warn!("MetadataRequest : stale");
            return Ok(ExternalMessage::SyncBlockHeaders(vec![]));
        }

        let batch_size = Self::MAX_BATCH_SIZE
            .min(request.to_height.saturating_sub(request.from_height) as usize);
        let mut metas = Vec::with_capacity(batch_size);
        let Some(block) = self.db.get_block(BlockFilter::Height(request.to_height))? else {
            warn!("MetadataRequest : missing");
            return Ok(ExternalMessage::SyncBlockHeaders(vec![]));
        };

        let mut hash = block.hash();
        while metas.len() <= batch_size {
            let Some(brt) = self
                .db
                .get_block_and_receipts_and_transactions(hash.into())?
            else {
                break; // that's all we have!
            };
            let header = brt.block.header;
            let parent_hash = brt.block.parent_hash();

            let encoded_size = self.size_cache.get(&hash).cloned().unwrap_or_else(|| {
                // pseudo-LRU approximation
                if self.size_cache.len() > Self::MAX_CACHE_SIZE {
                    let mut rng = rand::thread_rng();
                    self.size_cache.retain(|_, _| rng.gen_bool(0.99));
                }
                // A large block can cause a node to get stuck syncing since no node can respond to the request in time.
                let proposal = self.brt_to_proposal(brt);
                let encoded_size =
                    cbor4ii::serde::to_vec(Vec::with_capacity(1024 * 1024), &proposal)
                        .unwrap()
                        .len();
                self.size_cache.insert(hash, encoded_size);
                encoded_size
            });

            // insert the sync size
            metas.push(SyncBlockHeader {
                header,
                size_estimate: encoded_size,
            });
            hash = parent_hash;

            if header.number.saturating_sub(1) < self.zq2_floor_height {
                warn!("MetadataRequest : skipping ZQ1");
                break;
            }
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
            unimplemented!("RequestMissingHeaders : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if !self.in_flight.is_empty() || self.in_pipeline > self.max_batch_size {
            // anything more than this and we cannot be sure whether the segment hits history
            debug!(
                "RequestMissingHeaders : syncing {}/{} blocks",
                self.in_pipeline, self.max_batch_size
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
            warn!("RequestMissingHeaders : insufficient peers");
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
            unimplemented!("DoMissingMetadata : invalid state");
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

                debug!(?range, from = %peer_info.peer_id,
                    "DoMissingMetadata : requesting ({num}/{num_peers})",
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
                warn!("DoMissingMetadata : insufficient peers");
                break;
            }
        }
        Ok(())
    }

    /// Phase 5: Store Proposals
    ///
    /// These need only be stored, not executed - IN DESCENDING ORDER.
    fn store_proposals(&mut self, response: Vec<BlockTransactionsReceipts>) -> Result<()> {
        let SyncState::Phase4((mut number, mut hash)) = self.state else {
            unimplemented!("StoreProposals : invalid state");
        };
        let response = response
            .into_iter()
            .sorted_by_key(|p| Reverse(p.block.number()))
            .collect_vec();

        // Store it from high to low
        for BlockTransactionsReceipts {
            block,
            transaction_receipts,
        } in response
        {
            // Check for correct order
            if number == block.number() && hash == block.hash() {
                number = number.saturating_sub(1);
                hash = block.header.qc.block_hash;
            } else {
                error!(
                    "StoreProposals : unexpected proposal number={number} != {}; hash={hash} != {}",
                    block.number(),
                    block.hash(),
                );
                return Ok(());
            }

            // Verify ZQ2 blocks only - ZQ1 blocks have faux block hashes, to maintain history.
            if block.verify_hash().is_err() && block.number() >= self.zq2_floor_height {
                return Err(anyhow::anyhow!(
                    "StoreProposals : unverified {}",
                    block.number()
                ));
            }
            trace!(
                number = %block.number(), hash = %block.hash(),
                "StoreProposals : applying",
            );

            // Store/Ignore - if it already exists.
            self.db.with_sqlite_tx(|sqlite_tx| {
                    // Insert block
                    self.db.insert_block_with_db_tx(sqlite_tx, &block).ok();
                    // Insert transactions/receipts
                    for (st, rt) in transaction_receipts {
                        // Verify transaction
                        if let Ok(vt) = st.clone().verify() {
                            self.db
                                .insert_transaction_with_db_tx(sqlite_tx, &vt.hash, &vt)?;
                        } else if block.number() < self.zq2_floor_height {
                            // FIXME: ZQ1 bypass
                            error!(number = %block.number(), index = %rt.index, hash = %rt.tx_hash, "StoreProposals : unverifiable");
                            self.db
                                .insert_transaction_with_db_tx(sqlite_tx, &rt.tx_hash, &st.verify_bypass(rt.tx_hash)?)?;
                        } else {
                            anyhow::bail!(
                                "StoreProposal : unverifiable transaction {}/{}/{}",
                                block.number(),
                                rt.index,
                                rt.tx_hash
                            )
                        }
                        self.db
                            .insert_transaction_receipt_with_db_tx(sqlite_tx, rt)?;
                    }
                    Ok(())
                })?;
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
            debug!(%rate, "InjectProposals : injected");
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
                warn!(number = %prev_highest, "InjectProposals : stuck");
                return Ok(false);
            }
        }

        // Increment proposals injected
        self.in_pipeline = self.in_pipeline.saturating_add(proposals.len());
        debug!(
            "InjectProposals : injecting {}/{}",
            proposals.len(),
            self.in_pipeline
        );

        // Just pump the Proposals back to ourselves.
        for p in proposals {
            trace!(
                number = %p.number(), hash = %p.hash(),
                "InjectProposals : applying",
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
        trace!(%number, "MarkReceivedProposal : received");
        self.in_pipeline = self.in_pipeline.saturating_sub(1);
        // perform next block transfers, where possible
        self.do_sync()
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
    pub fn get_sync_data(&self, db: Arc<Db>) -> Result<Option<SyncingStruct>> {
        if !self.am_syncing()? {
            return Ok(None);
        }

        let current_block = data_access::get_highest_canonical_block_number(db);

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

    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peers
            .peer_ids()
            .into_iter()
            .chain(self.in_flight.iter().map(|(p, _)| p.peer_id))
            .collect()
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
        peers.iter().filter(|p| p.score == best_score).count()
    }

    fn count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    fn peer_ids(&self) -> Vec<PeerId> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .map(|peer| peer.peer_id)
            .collect::<Vec<_>>()
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
        trace!("DoneWithPeer {} {:?}", peer.peer_id, downgrade);
        // Reinsert peers that are good
        if peer.score < u32::MAX {
            peer.score = peer.score.saturating_add(downgrade as u32);
            self.append_peer(peer);
        }
    }

    /// Add bulk peers
    pub fn add_peers(&self, peers: Vec<PeerId>) {
        debug!("AddPeers {:?}", peers);
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
            score: peers.iter().map(|p| p.score).min().unwrap_or_default(),
            peer_id: peer,
            last_used: Instant::now(),
        };
        // ensure that it is unique
        peers.retain(|p| p.peer_id != peer);
        peers.push(new_peer);
        trace!("AddPeer {peer}/{}", peers.len());
    }

    /// Remove a peer from the list of peers.
    pub fn remove_peer(&self, peer: PeerId) {
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|p: &PeerInfo| p.peer_id != peer);
        trace!("RemovePeer {peer}/{}", peers.len());
    }

    /// Get the next best peer to use
    fn get_next_peer(&self) -> Option<PeerInfo> {
        if let Some(mut peer) = self.peers.lock().unwrap().pop() {
            peer.last_used = std::time::Instant::now();
            trace!(peer = % peer.peer_id, score= %peer.score, "GetNextPeer");
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

#[derive(Debug, Serialize, Deserialize)]
struct SyncMarker {
    hash: Hash,
    peer: PeerId,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncHeader {
    number: u64,
    parent: Hash,
}

#[derive(Debug)]
struct SyncSegments {
    db: sled::Db,
    counter: usize,
}

impl SyncSegments {
    fn new() -> Self {
        let mut sync = SyncSegments {
            counter: 0,
            // use an in-memory database first, as it will be replaced with a persistent one later
            db: sled::Config::new()
                .cache_capacity(1024 * 1024) // 1MB is enough
                .temporary(true)
                .open()
                .unwrap(),
        };
        sync.empty_sync_metadata().unwrap();
        sync
    }

    /// Returns the number of stored sync segments
    fn count_sync_segments(&self) -> Result<usize> {
        Ok(self.counter)
    }

    /// Pop the stack, for active-sync from marker (inclusive)
    #[allow(clippy::type_complexity)]
    fn pop_last_sync_segment(
        &mut self,
    ) -> Result<Option<(Vec<Hash>, PeerInfo, BlockHeader, RangeInclusive<u64>)>> {
        // pop the marker
        if self.counter == 0 {
            tracing::warn!("sync counter = 0");
            return Ok(None);
        }

        let markers = self.db.open_tree("markers")?;
        let SyncMarker { mut hash, peer } =
            if let Some(marker) = markers.remove(self.counter.to_be_bytes())? {
                self.counter = self.counter.saturating_sub(1);
                cbor4ii::serde::from_slice::<SyncMarker>(marker.to_vec().as_slice())?
            } else {
                tracing::warn!(counter = %self.counter, "marker not found");
                return Ok(None);
            };

        let headers = self.db.open_tree("headers")?;
        let high_at = if let Some(header) = headers.get(hash.0)? {
            let header = cbor4ii::serde::from_slice::<SyncHeader>(header.to_vec().as_slice())?;
            header.number
        } else {
            tracing::warn!(%hash, "header not found");
            return Ok(None);
        };

        let high_hash = hash;
        let mut low_at = 0;

        // retrieve the segment
        let mut hashes = Vec::with_capacity(100);
        while let Some(header) = headers.remove(hash.0)? {
            let header = cbor4ii::serde::from_slice::<SyncHeader>(header.to_vec().as_slice())?;
            low_at = header.number;
            hashes.push(hash);
            hash = header.parent;
        }

        // synthesise results
        let peer = PeerInfo {
            last_used: Instant::now(),
            score: u32::MAX,
            peer_id: peer,
        };

        let mut faux_marker = BlockHeader::genesis(Hash::ZERO);
        faux_marker.number = high_at;
        faux_marker.hash = high_hash;

        Ok(Some((hashes, peer, faux_marker, low_at..=high_at)))
    }

    /// Pushes a particular segment into the stack.
    fn push_sync_segment(&mut self, peer: &PeerInfo, hash: Hash) -> Result<()> {
        // do not double-push
        let markers = self.db.open_tree("markers")?;
        if let Some(marker) = markers.get(self.counter.to_be_bytes())? {
            let marker = cbor4ii::serde::from_slice::<SyncMarker>(marker.to_vec().as_slice())?;
            if hash != marker.hash {
                let marker = SyncMarker {
                    hash,
                    peer: peer.peer_id,
                };
                let marker = cbor4ii::serde::to_vec(Vec::with_capacity(1024), &marker)?;
                self.counter = self.counter.saturating_add(1);
                markers.insert(self.counter.to_be_bytes(), marker)?;
            }
        }
        Ok(())
    }

    /// Bulk inserts a bunch of metadata.
    fn insert_sync_metadata(&mut self, meta: &BlockHeader) -> Result<()> {
        let header = SyncHeader {
            number: meta.number,
            parent: meta.qc.block_hash,
        };
        let header = cbor4ii::serde::to_vec(Vec::with_capacity(1024), &header)?;
        let headers = self.db.open_tree("headers")?;
        headers.insert(meta.hash.0, header)?;
        Ok(())
    }

    /// Empty the metadata table.
    fn empty_sync_metadata(&mut self) -> Result<()> {
        self.counter = 0;

        // drop existing db, reopen new one, to free up disk space
        let path = tempdir().unwrap();
        self.db = sled::Config::new()
            .cache_capacity(1024 * 1024) // 1MB is enough
            .path(path.keep())
            .mode(sled::Mode::LowSpace)
            .temporary(true)
            .open()?;

        // forcibly insert a 0-th marker
        let marker = SyncMarker {
            hash: Hash::ZERO,
            peer: PeerId::random(),
        };
        let zero = cbor4ii::serde::to_vec(Vec::with_capacity(1024), &marker).unwrap_or_default();
        let markers = self.db.open_tree("markers")?;
        markers.insert(self.counter.to_be_bytes(), zero)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.db.open_tree("markers")?.flush()?;
        self.db.open_tree("headers")?.flush()?;
        Ok(())
    }
}

// FIXME: Find a better way to do this, other than checking for debug/release build.
// For the purpose of testing, we need a smaller prune interval to ensure that the test cases run faster.
#[cfg(feature = "fake_time")]
pub const MIN_PRUNE_INTERVAL: u64 = 10;
#[cfg(not(feature = "fake_time"))]
pub const MIN_PRUNE_INTERVAL: u64 = 300;
