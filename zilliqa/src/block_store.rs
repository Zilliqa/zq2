use std::{
    cmp,
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{anyhow, Result};
use libp2p::PeerId;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::ops::Range;
use tracing::*;

use crate::{
    cfg::NodeConfig,
    constants,
    crypto::Hash,
    db::Db,
    message::{Block, BlockRequest, BlockStrategy, ExternalMessage, Proposal},
    node::{MessageSender, OutgoingMessageFailure, RequestId},
    range_map::RangeMap,
    time::SystemTime,
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
/// we've seen (whether its part of our chain or not). If we've seen a view greater than the view of our latest
/// committed block, we want to send requests and attempt to download those missing blocks from other nodes.
///
/// We make requests for up to `max_blocks_in_flight` blocks at a time, in batches of `batch_size`.
///
/// TODO(#1096): Retries for blocks we request but never receive.
#[derive(Debug)]
pub struct BlockStore {
    db: Arc<Db>,
    block_cache: Arc<RwLock<LruCache<Hash, Block>>>,
    /// The maximum view of any proposal we have received, even if it is not part of our chain yet.
    highest_known_view: u64,
    /// Information we keep about our peers' state.
    peers: BTreeMap<PeerId, PeerInfo>,
    /// The maximum view of blocks we've sent a request for.
    requested_view: u64,
    /// The maximum number of blocks to send requests for at a time.
    max_blocks_in_flight: u64,
    /// The maximum number of blocks to request at a time.
    batch_size: u64,
    /// When a request to a peer fails, do not send another request to this peer for this amount of time.
    failed_request_sleep_duration: Duration,
    /// Our block strategies.
    strategies: Vec<BlockStrategy>,
    /// Last time we updated our availability - we do this at most once a second or so to avoid spam
    available_blocks: Vec<BlockStrategy>,
    available_blocks_updated: Option<SystemTime>,
    /// Buffered block proposals, indexed by their parent hash. These are proposals we've received, whose parents we
    /// haven't yet seen. We want to be careful about buffering too many proposals. There is no guarantee or proof that
    /// any of them will eventually form our canonical chain. Therefore we limit the number of buffered proposals to
    /// `max_blocks_in_flight + 100`. This number is chosen because it makes it probable we will always be able to
    /// handle pending requests made by ourselves that arrive out-of-order, while also giving some extra space for
    /// newly created blocks that arrive while we are syncing.
    buffered: LruCache<Hash, Proposal>,
    /// Requests we would like to send, but haven't been able to (e.g. because we have no peers).
    unserviceable_requests: RangeMap,
    message_sender: MessageSender,

    /// Clock pointer - see request_blocks()
    clock: usize,
}

/// Data about block availability sent between peers
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockAvailability {
    /// None means no information, Some([]) means the other node shouldn't be relied upon for any blocks at all.
    strategies: Option<Vec<BlockStrategy>>,
    /// The largest view we've seen from a block that this peer sent us.
    highest_known_view: u64,
}

#[derive(Clone, Debug)]
struct PeerInfo {
    /// Availability from this peer
    availability: BlockAvailability,
    /// When did we last update availability?
    availability_updated_at: Option<SystemTime>,
    /// Last availability query - don't send them too often.
    availability_requested_at: Option<SystemTime>,
    /// The number of blocks we've requested from the peer.
    requested_blocks: u64,
    /// Requests we've sent to the peer.
    pending_requests: LruCache<RequestId, (SystemTime, u64, u64)>,
    /// If `Some`, the time of the most recently failed request.
    last_request_failed_at: Option<SystemTime>,
}

impl PeerInfo {
    fn new(request_capacity: NonZeroUsize) -> Self {
        Self {
            availability: BlockAvailability::new(),
            availability_updated_at: None,
            availability_requested_at: None,
            requested_blocks: 0,
            pending_requests: LruCache::new(request_capacity),
            last_request_failed_at: None,
        }
    }

    /// Do we have (recent) availability, or should we get it again?
    fn have_recent_availability(&self) -> bool {
        self.availability_updated_at.is_some()
    }

    /// Converts a set of block strategies into a rangemap
    fn get_ranges(&self, max_view: Option<u64>) -> RangeMap {
        let mut result = RangeMap::new();
        if let Some(strat) = &self.availability.strategies {
            let mut max_end: Option<u64> = None;
            let mut is_opportunistic = false;
            for s in strat {
                match s {
                    BlockStrategy::CachedViewRange(views, until_view) => {
                        if self.availability.highest_known_view <= *until_view {
                            result.with_range(&views);
                            max_end = Some(
                                max_end.map_or(views.end - 1, |v| std::cmp::max(v, views.end - 1)),
                            );
                        }
                    }
                    BlockStrategy::Opportunistic => {
                        is_opportunistic = true;
                    }
                }
            }
            if is_opportunistic {
                if let Some(v) = max_end {
                    if let Some(w) = max_view {
                        result.with_range(&Range {
                            start: v,
                            end: w + 1,
                        });
                    }
                }
            }
        }
        result
    }
}

/// Data about a peer
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerInfoStatus {
    availability: BlockAvailability,
    availability_updated_at: Option<u64>,
    requested_blocks: u64,
    pending_requests: Vec<(String, SystemTime, u64, u64)>,
    last_request_failed_at: Option<u64>,
}

/// Data about the block store, used for debugging.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockStoreStatus {
    highest_known_view: u64,
    views_held: Vec<Range<u64>>,
    peers: Vec<(String, PeerInfoStatus)>,
    availability: Option<Vec<BlockStrategy>>,
}

impl BlockStoreStatus {
    pub fn new(block_store: &mut BlockStore) -> Result<Self> {
        let peers = block_store
            .peers
            .iter()
            .map(|(k, v)| (format!("{:?}", k), PeerInfoStatus::new(&v)))
            .collect::<Vec<_>>();

        Ok(Self {
            highest_known_view: block_store.highest_known_view,
            views_held: block_store.db.get_view_ranges()?,
            peers,
            availability: block_store.availability()?,
        })
    }
}

impl PeerInfoStatus {
    // Annoyingly, this can't (easily) be allowed to fail without making generating debug info hard.
    fn new(info: &PeerInfo) -> Self {
        fn s_from_time(q: Option<SystemTime>) -> Option<u64> {
            q.map(|z| {
                z.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs()
            })
        }
        let pending_requests = info
            .pending_requests
            .iter()
            .map(|(k, v)| (format!("{:?}", k), v.0, v.1, v.2))
            .collect::<Vec<_>>();
        Self {
            availability: info.availability.clone(),
            availability_updated_at: s_from_time(info.availability_updated_at),
            requested_blocks: info.requested_blocks,
            pending_requests,
            last_request_failed_at: s_from_time(info.last_request_failed_at),
        }
    }
}

impl BlockAvailability {
    pub fn new() -> Self {
        Self {
            strategies: None,
            highest_known_view: 0,
        }
    }
}

impl BlockStore {
    pub fn new(config: &NodeConfig, db: Arc<Db>, message_sender: MessageSender) -> Result<Self> {
        Ok(BlockStore {
            db,
            block_cache: Arc::new(RwLock::new(LruCache::new(NonZeroUsize::new(5).unwrap()))),
            highest_known_view: 0,
            peers: BTreeMap::new(),
            requested_view: 0,
            max_blocks_in_flight: config.max_blocks_in_flight,
            batch_size: config.block_request_batch_size,
            failed_request_sleep_duration: config.failed_request_sleep_duration,
            strategies: vec![BlockStrategy::Opportunistic],
            available_blocks: vec![],
            available_blocks_updated: None,
            buffered: LruCache::new(
                NonZeroUsize::new(config.max_blocks_in_flight as usize + 100).unwrap(),
            ),
            unserviceable_requests: RangeMap::new(),
            message_sender,
            clock: 0,
        })
    }

    /// Create a read-only clone of this [BlockStore]. The read-only property must be upheld by the caller - Calling
    /// any `&mut self` methods on the returned [BlockStore] will lead to problems. This clone is cheap.
    pub fn clone_read_only(&self) -> Arc<Self> {
        Arc::new(BlockStore {
            db: self.db.clone(),
            block_cache: self.block_cache.clone(),
            highest_known_view: 0,
            peers: BTreeMap::new(),
            requested_view: 0,
            max_blocks_in_flight: 0,
            batch_size: 0,
            failed_request_sleep_duration: Duration::ZERO,
            strategies: self.strategies.clone(),
            available_blocks: Vec::new(),
            available_blocks_updated: None,
            buffered: LruCache::new(NonZeroUsize::new(1).unwrap()),
            unserviceable_requests: RangeMap::new(),
            message_sender: self.message_sender.clone(),
            clock: 0,
        })
    }

    /// Update someone else's availability
    pub fn update_availability(
        &mut self,
        from: PeerId,
        avail: &Option<Vec<BlockStrategy>>,
    ) -> Result<()> {
        let the_peer = self.peer_info(from);
        the_peer.availability.strategies.clone_from(avail);
        the_peer.availability_updated_at = Some(SystemTime::now());
        Ok(())
    }

    /// Retrieve our availability.
    pub fn availability(&mut self) -> Result<Option<Vec<BlockStrategy>>> {
        let mut to_return = self.strategies.clone();
        let now = SystemTime::now();
        if self.available_blocks_updated.map_or(true, |x| {
            now.duration_since(x).unwrap_or(Duration::ZERO)
                > Duration::from_secs(constants::RECOMPUTE_BLOCK_AVAILABILITY_AFTER_S)
        }) {
            trace!("Updating available views");
            self.available_blocks = self
                .db
                .get_view_ranges()?
                .iter()
                .map(|x| BlockStrategy::CachedViewRange(x.clone(), 0))
                .collect();
            self.available_blocks_updated = Some(now);
        }
        to_return.extend(self.available_blocks.iter().cloned());
        Ok(Some(to_return))
    }

    /// Buffer a block proposal whose parent we don't yet know about.
    pub fn buffer_proposal(&mut self, from: PeerId, proposal: Proposal) -> Result<()> {
        let view = proposal.view();

        self.buffered.push(proposal.header.qc.block_hash, proposal);

        // If this is the highest block we've seen, remember its view.
        if view > self.highest_known_view {
            trace!(view, "new highest known view");
            self.highest_known_view = view;
        }

        let peer = self.peer_info(from);
        if view > peer.availability.highest_known_view {
            trace!(%from, view, "new highest known view for peer");
            peer.availability.highest_known_view = view;
        }

        self.request_missing_blocks()?;

        Ok(())
    }

    pub fn best_peer(&self, view: u64) -> Option<PeerId> {
        let (best, _) = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.availability.highest_known_view >= view)
            // If the last request failed, don't send requests to this peer for 10 seconds.
            .filter(|(_, peer)| {
                peer.last_request_failed_at
                    .and_then(|at| at.elapsed().ok())
                    .map(|time_since| time_since > self.failed_request_sleep_duration)
                    .unwrap_or(true)
            })
            .min_by_key(|(_, peer)| peer.requested_blocks)?;
        Some(*best)
    }

    pub fn retry_us_requests(&mut self) -> Result<()> {
        // Attempt to send pending requests if we can.
        // TODO: find a better way to move this.
        let us_requests = self.unserviceable_requests.clone();
        trace!("re-attempting u/s requests {us_requests:?}");
        self.unserviceable_requests = RangeMap::new();
        self.request_blocks(&us_requests)?;
        Ok(())
    }

    pub fn request_missing_blocks(&mut self) -> Result<()> {
        trace!("request_missing_blocks");
        // Get the highest view we currently have committed to our chain.
        let current_view = self
            .get_block_by_number(
                self.db
                    .get_highest_block_number()?
                    .ok_or_else(|| anyhow!("no highest block"))?,
            )?
            .ok_or_else(|| anyhow!("missing highest block"))?
            .view();
        // We've already got any block we've previously committed, so don't request them again.
        if self.requested_view < current_view {
            self.requested_view = current_view;
        }

        self.retry_us_requests()?;

        // If we think the network might be ahead of where we currently are, attempt to download the missing blocks.
        if self.highest_known_view > current_view {
            trace!(
                current_view,
                self.highest_known_view,
                self.requested_view,
                self.max_blocks_in_flight,
                self.batch_size,
                "missing some blocks"
            );
            // The first condition checks that there are more blocks we haven't requested yet. The second condition
            // ensures that we respect our `max_blocks_in_flight` parameter. Note that we subtract the configured
            // `batch_size` from this to ensure our new requests don't overlap with previous in-flight requests.
            while self.requested_view < self.highest_known_view
                && (self.requested_view - current_view)
                    <= (self.max_blocks_in_flight - self.batch_size)
            {
                let from = self.requested_view + 1;
                let to = cmp::min(
                    self.requested_view + self.batch_size,
                    self.highest_known_view,
                );
                trace!("requesting blocks {from} to {to}");
                self.request_blocks(&RangeMap::from_closed_interval(from, to))?;
                self.requested_view = to;
            }
        }

        Ok(())
    }

    /// Make a request for the blocks associated with a range of views. Returns `true` if a request was made and `false` if the request had to be
    /// buffered because no peers were available.
    /// Public so we can trigger it from the debug API
    pub fn request_blocks(&mut self, req: &RangeMap) -> Result<bool> {
        let mut remain = req.clone();
        let to = req.max();

        trace!("request_blocks for {:?} clock {}", remain, self.clock);
        // If it's in flight, don't request it again.
        for (_, peer) in &self.peers {
            for (_, (_, start, end)) in &peer.pending_requests {
                let cand = RangeMap::from_range(&Range {
                    start: *start,
                    end: end + 1,
                });
                (_, remain) = remain.diff_inter(&cand);
            }
        }

        let now = SystemTime::now();
        let failed_request_sleep_duration = self.failed_request_sleep_duration;
        trace!("after removing in_flight {:?}", remain);
        for chance in 0..2 {
            trace!(
                "chance = {chance} clock = {} peers = {}",
                self.clock,
                self.peers.len()
            );
            self.clock = (self.clock + 1) % self.peers.len();
            // Slightly horrid - generate a list of peers which is the BTreeMap's list, shifted by clock.
            let peers = self
                .peers
                .keys()
                .skip(self.clock)
                .chain(self.peers.keys().take(self.clock))
                .cloned()
                .collect::<Vec<PeerId>>();

            for peer in &peers {
                trace!("peer = {peer}");
                // If the last request failed < 10s or so ago, skip this peer, unless we're second-chance in
                // which case, hey, why not?
                let (requests, remain, query_availability) = {
                    let peer_info = self.peer_info(*peer);
                    if chance == 0
                        && !peer_info
                            .last_request_failed_at
                            .and_then(|at| at.elapsed().ok())
                            .map(|time_since| time_since > failed_request_sleep_duration)
                            .unwrap_or(true)
                    {
                        trace!(".. Last request failed");
                        continue;
                    }

                    // Split ..
                    let ranges = peer_info.get_ranges(to);
                    trace!("ranges {ranges:?}");
                    let (req, rem) = ranges.diff_inter(&remain);
                    trace!("req {req:?} rem {rem:?}");
                    // If we are not about to make a request, and we do not have recent availability then
                    // make a synthetic request to get that availability.
                    let query_availability = req.is_empty()
                        && !peer_info.have_recent_availability()
                        && peer_info.availability_requested_at.map_or(true, |x| {
                            x.elapsed()
                                .map(|v| {
                                    v > Duration::from_millis(
                                        constants::REQUEST_PEER_VIEW_AVAILABILITY_NOT_BEFORE_MS,
                                    )
                                })
                                .unwrap_or(true)
                        });
                    (req, rem, query_availability)
                };

                if chance == 0 && query_availability {
                    trace!("Querying availability");
                    // Executive decision: Don't ask for any blocks here, because we are about to do so in duplicate
                    // later and we don't want to duplicate work - you could viably go for a slightly faster
                    // sync by just asking for all the blocks and letting the peer send what it has.
                    let message = ExternalMessage::BlockRequest(BlockRequest {
                        from_view: 0,
                        to_view: 0,
                    });
                    let peer_info = self.peer_info(*peer);
                    peer_info.availability_requested_at = Some(now);
                    let _ = self.message_sender.send_external_message(*peer, message);
                }

                trace!(" .. Requests to send: {:?}", requests);
                for request in requests.ranges.iter() {
                    if !request.is_empty() {
                        trace!(
                            "peer = {:?} request = {:?} remains = {:?}: sending block request",
                            peer,
                            request,
                            remain
                        );
                        // Yay!
                        let message = ExternalMessage::BlockRequest(BlockRequest {
                            from_view: request.start,
                            to_view: request.end,
                        });
                        let request_id =
                            self.message_sender.send_external_message(*peer, message)?;
                        self.peer_info(*peer)
                            .pending_requests
                            .put(request_id, (now, request.start, request.end));
                        break;
                    }
                }
            }
        }
        trace!("All done");
        if !remain.is_empty() {
            warn!("Could not find peers for views {:?}", remain);
            self.unserviceable_requests.with_range_map(&remain);
        }
        Ok(true)
    }

    pub fn get_block(&self, hash: Hash) -> Result<Option<Block>> {
        let mut block_cache = self
            .block_cache
            .write()
            .map_err(|e| anyhow!("Failed to get write access to block cache: {e}"))?;
        if let Some(block) = block_cache.get(&hash) {
            return Ok(Some(block.clone()));
        }
        let Some(block) = self.db.get_block_by_hash(&hash)? else {
            return Ok(None);
        };
        block_cache.put(hash, block.clone());
        Ok(Some(block))
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        let Some(hash) = self.db.get_block_hash_by_view(view)? else {
            return Ok(None);
        };
        self.get_block(hash)
    }

    pub fn get_highest_block_number(&self) -> Result<Option<u64>> {
        self.db.get_highest_block_number()
    }

    pub fn get_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        let Some(hash) = self.db.get_canonical_block_number(number)? else {
            return Ok(None);
        };
        self.get_block(hash)
    }

    pub fn process_block(
        &mut self,
        from: Option<PeerId>,
        block: Block,
    ) -> Result<Option<Proposal>> {
        trace!(?from, number = block.number(), hash = ?block.hash(), "insert block");
        self.db.insert_block(&block)?;
        self.db
            .set_canonical_block_number(block.number(), block.hash())?;

        if let Some(from) = from {
            let peer = self.peer_info(from);
            peer.requested_blocks = peer.requested_blocks.saturating_sub(1);
            if block.view() > peer.availability.highest_known_view {
                trace!(%from, view = block.view(), "new highest known view for peer");
                peer.availability.highest_known_view = block.view();
            }
        }

        if let Some(child) = self.buffered.pop(&block.hash()) {
            return Ok(Some(child));
        }

        Ok(None)
    }

    pub fn report_outgoing_message_failure(
        &mut self,
        failure: OutgoingMessageFailure,
    ) -> Result<()> {
        let peer_info = self.peer_info(failure.peer);
        let Some((_, from, to)) = peer_info.pending_requests.pop(&failure.request_id) else {
            // A request we didn't know about failed. It must have been sent by someone else.
            return Ok(());
        };
        peer_info.last_request_failed_at = Some(SystemTime::now());

        trace!("outgoing_message_failure: re-requesting {from} - {to}");
        self.request_blocks(&RangeMap::from_closed_interval(from, to))?;

        Ok(())
    }

    fn peer_info(&mut self, peer: PeerId) -> &mut PeerInfo {
        // Ensure we have enough capacity to theoretically keep track of all requests being sent to a single node at
        // once.
        let capacity =
            NonZeroUsize::new((self.max_blocks_in_flight / self.batch_size) as usize).unwrap();
        self.peers
            .entry(peer)
            .or_insert_with(|| PeerInfo::new(capacity))
    }

    pub fn forget_block_range(&mut self, blocks: Range<u64>) -> Result<()> {
        Ok(self.db.forget_block_range(blocks)?)
    }

    pub fn contains_block(&mut self, block_hash: &Hash) -> Result<bool> {
        Ok(self.db.contains_block(block_hash)?)
    }
}
