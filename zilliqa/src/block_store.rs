use std::{
    cmp,
    collections::{BTreeMap, HashMap},
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

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockCacheEntry {
    pub parent_hash: Hash,
    pub from: PeerId,
    pub proposal: Proposal,
}

impl BlockCacheEntry {
    pub fn new(parent_hash: Hash, from: PeerId, proposal: Proposal) -> Self {
        Self {
            parent_hash,
            from,
            proposal,
        }
    }
}

/// A block cache.
/// We need to be careful to conserve block space in the presence of block flooding attacks, and we need to
/// make sure we don't lose blocks that form part of the main chain repeatedly, else we will never be able
/// to construct it.
/// Similarly, we should ensure that we always buffer proposals close to the head of the tree, else we will
/// lose sync frequently and have to request, which will slow down block production.
///
/// An easy way to do this is to put a hash of the node address (actually, we just use the low bits) in the
/// bottom (log2(N_WAYS)) bits of the view number. We then evict the largest tag le (max_view - buffer).
///
/// I don't think it actually matters whether we use the view or the block number here, since we're not using
/// fixed-size arrays.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockCache {
    /// Caches proposals that are not yet blocks, and are before the tail cache.
    pub cache: BTreeMap<u128, BlockCacheEntry>,
    /// Caches proposals close to the head.
    pub tail: BTreeMap<u128, BlockCacheEntry>,
    /// The head cache - this caches
    /// An index into the cache by parent hash
    pub by_parent_hash: HashMap<Hash, u128>,
}

impl BlockCache {
    pub fn new() -> Self {
        Self {
            cache: BTreeMap::new(),
            tail: BTreeMap::new(),
            by_parent_hash: HashMap::new(),
        }
    }

    pub fn key_from_number(&self, peer: &PeerId, view_num: u64) -> u128 {
        let ways = peer.to_bytes().pop().unwrap_or(0x00);
        let shift = 8 - constants::BLOCK_CACHE_LOG2_WAYS;
        u128::from(ways >> shift) | (u128::from(view_num) << shift)
    }

    pub fn min_key_for_view(&self, view: u64) -> u128 {
        let shift = 8 - constants::BLOCK_CACHE_LOG2_WAYS;
        u128::from(view) << shift
    }

    pub fn min_tail_key(&self, highest_known_view: u64) -> u128 {
        let shift = 8 - constants::BLOCK_CACHE_LOG2_WAYS;
        let highest_key = u128::from(highest_known_view + 1) << shift;
        highest_key - u128::try_from(constants::BLOCK_CACHE_TAIL_BUFFER_ENTRIES).unwrap()
    }

    pub fn destructive_proposal_from_parent_hash(
        &mut self,
        hash: &Hash,
    ) -> Option<(PeerId, Proposal)> {
        if let Some(key) = self.by_parent_hash.remove(hash) {
            let maybe = self
                .cache
                .remove(&key)
                .or_else(|| self.tail.remove(&key))
                .map(|x| (x.from, x.proposal));
            maybe
        } else {
            None
        }
    }

    pub fn trim(&mut self, highest_confirmed_view: u64, max_blocks_in_flight: u64) -> Result<()> {
        // Now zap any entries we don't need any more.
        let mut did_anything = true;
        let lowest_ignored_key = self.min_key_for_view(highest_confirmed_view);
        let cache_entries = max_blocks_in_flight << constants::BLOCK_CACHE_LOG2_WAYS;
        debug!("trim: lowest_ignored_key = {0}", lowest_ignored_key);
        // debug!("trim: cache had: {0}", self.extant_block_ranges()?);
        while did_anything {
            did_anything = false;

            if let Some((k, _)) = self.cache.first_key_value() {
                if *k <= lowest_ignored_key {
                    // Kill it!
                    self.cache
                        .pop_first()
                        .and_then(|(_, v)| self.by_parent_hash.remove(&v.parent_hash));
                    did_anything = true;
                }
            }
            if let Some((k, _)) = self.tail.first_key_value() {
                if *k <= lowest_ignored_key {
                    self.tail
                        .pop_first()
                        .and_then(|(_, v)| self.by_parent_hash.remove(&v.parent_hash));
                    did_anything = true;
                }
            }
        }

        while self.cache.len() > usize::try_from(cache_entries).unwrap() {
            self.cache
                .pop_last()
                .and_then(|(_, v)| self.by_parent_hash.remove(&v.parent_hash));
        }
        while self.tail.len() > constants::BLOCK_CACHE_TAIL_BUFFER_ENTRIES {
            self.tail
                .pop_first()
                .and_then(|(_, v)| self.by_parent_hash.remove(&v.parent_hash));
        }

        // debug!("cache now has: {0}", self.extant_block_ranges()?);
        // Both caches are now at most the "right" number of entries long.
        Ok(())
    }

    /// Insert this proposal into the cache.
    pub fn insert(
        &mut self,
        from: &PeerId,
        parent_hash: &Hash,
        proposal: Proposal,
        highest_confirmed_view: u64,
        highest_known_view: u64,
        max_blocks_in_flight: u64,
    ) -> Result<()> {
        fn insert_with_replacement(
            into: &mut BTreeMap<u128, BlockCacheEntry>,
            by_parent_hash: &mut HashMap<Hash, u128>,
            from: &PeerId,
            parent_hash: &Hash,
            key: u128,
            value: Proposal,
        ) {
            into.insert(key, BlockCacheEntry::new(*parent_hash, from.clone(), value))
                .map(|entry| by_parent_hash.remove(&entry.parent_hash));
            by_parent_hash.insert(*parent_hash, key);
        }

        if proposal.header.view <= highest_confirmed_view {
            // nothing to do.
            return Ok(());
        }
        // First, insert us.
        let key = self.key_from_number(from, proposal.header.view);
        if key > self.min_tail_key(highest_known_view) {
            insert_with_replacement(
                &mut self.tail,
                &mut self.by_parent_hash,
                &from,
                parent_hash,
                key,
                proposal,
            );
        } else {
            insert_with_replacement(
                &mut self.cache,
                &mut self.by_parent_hash,
                &from,
                parent_hash,
                key,
                proposal,
            );
        }
        // Now evict the worst entry
        self.trim(highest_confirmed_view, max_blocks_in_flight)?;
        Ok(())
    }

    // For debugging - what view number ranges are in the cache?
    pub fn extant_block_ranges(&self) -> Result<RangeMap> {
        let mut result = RangeMap::new();
        let shift = 8 - constants::BLOCK_CACHE_LOG2_WAYS;
        for key in self.cache.keys() {
            let _ = u128::try_into(key >> shift).map(|x| result.with_number(x));
        }
        for key in self.tail.keys() {
            let _ = u128::try_into(key >> shift).map(|x| result.with_number(x));
        }
        Ok(result)
    }

    pub fn summarise(
        &self,
    ) -> Result<(
        Vec<(String, u64, String)>,
        Vec<(String, u64, String)>,
        Vec<(String, String)>,
    )> {
        let mut from_cache: Vec<(String, u64, String)> = Vec::new();
        for (k, v) in &self.cache {
            from_cache.push((
                format!("{:0x}", k),
                v.proposal.header.number,
                format!("{:?}", v.parent_hash),
            ));
        }
        let mut from_tail: Vec<(String, u64, String)> = Vec::new();
        for (k, v) in &self.tail {
            from_tail.push((
                format!("{:0x}", k),
                v.proposal.header.number,
                format!("{:?}", v.parent_hash),
            ));
        }
        let mut from_idx: Vec<(String, String)> = Vec::new();
        for (hash, key) in &self.by_parent_hash {
            from_idx.push((format!("{:?}", hash), format!("{:0x}", key)));
        }
        Ok((from_cache, from_tail, from_idx))
    }
}

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
///
///

#[derive(Debug)]
pub struct BlockStore {
    db: Arc<Db>,
    block_cache: Arc<RwLock<LruCache<Hash, Block>>>,
    /// The maximum view of any proposal we have received, even if it is not part of our chain yet.
    highest_known_view: u64,
    /// Highest confirmed view - blocks we know to be correct.
    highest_confirmed_view: u64,
    /// Information we keep about our peers' state.
    peers: BTreeMap<PeerId, PeerInfo>,
    /// The maximum view of blocks we've sent a request for.
    requested_view: u64,
    /// The maximum number of blocks to send requests for at a time.
    max_blocks_in_flight: u64,
    /// When a request to a peer fails, do not send another request to this peer for this amount of time.
    failed_request_sleep_duration: Duration,
    /// Our block strategies.
    strategies: Vec<BlockStrategy>,
    /// Last time we updated our availability - we do this at most once a second or so to avoid spam
    available_blocks: Vec<BlockStrategy>,
    available_blocks_updated: Option<SystemTime>,

    /// Buffered block proposals.
    buffered: BlockCache,
    /// Requests we would like to send, but haven't been able to (e.g. because we have no peers).
    unserviceable_requests: Option<RangeMap>,
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
    pending_requests: HashMap<RequestId, (SystemTime, u64, u64)>,
    /// If `Some`, the time of the most recently failed request.
    last_request_failed_at: Option<SystemTime>,
}

impl PeerInfo {
    fn new(_request_capacity: NonZeroUsize) -> Self {
        Self {
            availability: BlockAvailability::new(),
            availability_updated_at: None,
            availability_requested_at: None,
            requested_blocks: 0,
            pending_requests: HashMap::new(),
            last_request_failed_at: None,
        }
    }

    /// Do we have availability, or should we get it again?
    fn have_availability(&self) -> bool {
        self.availability_updated_at.is_some()
    }

    /// Converts a set of block strategies into a rangemap
    fn get_ranges(&self, max_view: Option<u64>) -> RangeMap {
        let mut result = RangeMap::new();
        if let Some(strat) = &self.availability.strategies {
            let mut max_end: Option<u64> = None;
            let mut last_n: Option<u64> = None;
            for s in strat {
                match s {
                    BlockStrategy::CachedViewRange(views, until_view) => {
                        if until_view.map_or(true, |x| self.availability.highest_known_view <= x) {
                            result.with_range(&views);
                            max_end = Some(
                                max_end.map_or(views.end - 1, |v| std::cmp::max(v, views.end - 1)),
                            );
                        }
                    }
                    BlockStrategy::Latest(n) => {
                        last_n = Some(last_n.map_or(*n, |x| std::cmp::max(x, *n)));
                    }
                }
            }
            if let Some(the_n) = last_n {
                if let Some(max_view_nr) = max_view {
                    let start = if the_n >= max_view_nr {
                        0
                    } else {
                        max_view_nr - the_n
                    };
                    result.with_range(&Range {
                        start,
                        end: max_view_nr,
                    });
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
            highest_confirmed_view: 0,
            peers: BTreeMap::new(),
            requested_view: 0,
            max_blocks_in_flight: config.max_blocks_in_flight,
            failed_request_sleep_duration: config.failed_request_sleep_duration,
            strategies: vec![BlockStrategy::Latest(constants::RETAINS_LAST_N_BLOCKS)],
            available_blocks: vec![],
            available_blocks_updated: None,
            buffered: BlockCache::new(),
            unserviceable_requests: None,
            message_sender,
            clock: 0,
        })
    }

    pub fn get_buffered(
        &self,
    ) -> Result<(
        Vec<(String, u64, String)>,
        Vec<(String, u64, String)>,
        Vec<(String, String)>,
    )> {
        self.buffered.summarise()
    }

    /// Create a read-only clone of this [BlockStore]. The read-only property must be upheld by the caller - Calling
    /// any `&mut self` methods on the returned [BlockStore] will lead to problems. This clone is cheap.
    pub fn clone_read_only(&self) -> Arc<Self> {
        Arc::new(BlockStore {
            db: self.db.clone(),
            block_cache: self.block_cache.clone(),
            highest_known_view: 0,
            highest_confirmed_view: 0,
            peers: BTreeMap::new(),
            requested_view: 0,
            max_blocks_in_flight: 0,
            failed_request_sleep_duration: Duration::ZERO,
            strategies: self.strategies.clone(),
            available_blocks: Vec::new(),
            available_blocks_updated: None,
            buffered: BlockCache::new(),
            unserviceable_requests: None,
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
    /// We need to do this by view range, which means that we need to account for views where there was no block.
    /// So, the underlying db function finds the view lower and upper bounds of our contiguous block ranges and we
    /// advertise those.
    /// This function overlays that with a timeout so we don't ask (and thus load the db) too often.
    pub fn availability(&mut self) -> Result<Option<Vec<BlockStrategy>>> {
        let mut to_return = self.strategies.clone();
        let now = SystemTime::now();
        if self.available_blocks_updated.map_or(true, |x| {
            now.duration_since(x).unwrap_or(Duration::ZERO)
                > Duration::from_secs(constants::RECOMPUTE_BLOCK_AVAILABILITY_AFTER_S)
        }) {
            debug!("Updating available views");
            self.available_blocks = self
                .db
                .get_view_ranges()?
                .iter()
                .map(|x| BlockStrategy::CachedViewRange(x.clone(), None))
                .collect();
            self.available_blocks_updated = Some(now);
        }
        to_return.extend(self.available_blocks.iter().cloned());
        Ok(Some(to_return))
    }

    /// Buffer a block proposal whose parent we don't yet know about.
    pub fn buffer_proposal(&mut self, from: PeerId, proposal: Proposal) -> Result<()> {
        let view = proposal.view();

        // If this is the highest block we've seen, remember its view.
        if view > self.highest_known_view {
            trace!(view, "new highest known view");
            self.highest_known_view = view;
        }

        trace!(
            "buffer_proposal: highest_confirmed_view {}",
            self.highest_confirmed_view
        );
        self.buffered.insert(
            &from,
            &proposal.header.qc.block_hash.clone(),
            proposal,
            self.highest_confirmed_view,
            self.highest_known_view,
            self.max_blocks_in_flight,
        )?;

        let peer = self.peer_info(from);
        if view > peer.availability.highest_known_view {
            trace!(%from, view, "new highest known view for peer");
            peer.availability.highest_known_view = view;
        }

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
        // Take this opportunity to update the highest confirmed view.
        self.highest_confirmed_view = std::cmp::max(self.highest_confirmed_view, current_view);
        trace!(
            "set highest_confirmed_view {0}",
            self.highest_confirmed_view
        );

        // First off, let's load up the unserviceable requests.
        let mut to_request = if let Some(us_requests) = self.unserviceable_requests.take() {
            us_requests
        } else {
            RangeMap::new()
        };

        // If we think the network might be ahead of where we currently are, attempt to download the missing blocks.
        // This is complicated, because we mustn't request more blocks than will fit in our cache, or we might
        // end up evicting the critical part of the chain..
        if self.highest_known_view > current_view {
            trace!(
                current_view,
                self.highest_known_view,
                self.requested_view,
                self.max_blocks_in_flight,
                "missing some blocks"
            );
            {
                // We need to request from current_view, because these blocks might never be returned by our peers
                // deduplication of requests is done one level lower - in request_blocks().
                let from = current_view + 1;
                // Never request more than current_view + max_blocks_in_flight, or the cache won't be able to hold
                // the responses and we'll end up being unable to reconstruct the chain. Not strictly true, because
                // the network will hold some blocks for us, but true enough that I think we ought to treat it as
                // such.
                let to = cmp::min(
                    cmp::min(self.requested_view, current_view) + self.max_blocks_in_flight,
                    self.highest_known_view,
                );
                trace!("requesting blocks {from} to {to}");
                to_request.with_range(&Range {
                    start: from,
                    end: to + 1,
                });
                self.requested_view = to;
            }
        }

        if !to_request.is_empty() {
            self.request_blocks(&to_request)?;
        }

        Ok(())
    }

    pub fn prune_pending_requests(&mut self) -> Result<()> {
        // In the good old days, we could've done this by linear interpolation on the timestamp.
        let current_time = SystemTime::now();
        let min_timeout_us = 1000 * constants::BLOCK_REQUEST_RESPONSE_TIMEOUT_MIN_MS;
        let us_per_block = constants::BLOCK_REQUEST_RESPONSE_TIMEOUT_PER_BLOCK_US;
        let highest_confirmed_view = self.highest_confirmed_view;
        for peer in self.peers.keys().cloned().collect::<Vec<PeerId>>() {
            let the_peer = self.peer_info(peer);
            the_peer.pending_requests = the_peer
                .pending_requests
                .iter()
                .filter_map(|(k, (v1, v2, v3))| {
                    // How long since this request was sent?
                    match current_time.duration_since(*v1) {
                        Ok(since) => {
                            let us = since.as_micros();
                            if us > u128::from(min_timeout_us) {
                                // Over the minimum timeout.
                                // How many blocks ahead do we need to be to not time out?
                                let view_just_not_timed_out = if let Ok(v) =
                                    u64::try_from((us - u128::from(min_timeout_us)) / u128::from(us_per_block) + u128::from(highest_confirmed_view)) {
                                        v
                                    } else {
                                        return None
                                    };
                                if *v3 <= view_just_not_timed_out {
                                    // We've timed out.
                                    trace!("timed out {v3} at {us}");
                                    None
                                } else if *v2 > view_just_not_timed_out {
                                    // Nothing's timed out - yay!
                                    Some((*k, (*v1, *v2, *v3)))
                                } else {
                                    trace!("partly timed out {v2},{v3} at {us} - {view_just_not_timed_out}:{v3}");
                                    Some((*k, (*v1, view_just_not_timed_out, *v3)))
                                }
                            } else {
                                Some((*k, (*v1, *v2, *v3)))
                            }
                        }
                        _ => None,
                    }
                })
                .collect();
        }
        Ok(())
    }

    pub fn retry_us_requests(&mut self) -> Result<()> {
        if let Some(us_requests) = self.unserviceable_requests.take() {
            self.request_blocks(&us_requests)?;
        }
        Ok(())
    }

    /// Make a request for the blocks associated with a range of views. Returns `true` if a request was made and `false` if the request had to be
    /// buffered because no peers were available.
    /// Public so we can trigger it from the debug API
    pub fn request_blocks(&mut self, req: &RangeMap) -> Result<bool> {
        let mut remain = req.clone();
        let to = req.max();

        // Prune the pending requests
        self.prune_pending_requests()?;

        trace!("request_blocks for {:?} clock {}", remain, self.clock);

        // If it's already buffered, don't request it again - wait for us to reject it and
        // then we can re-request.
        let extant = self.buffered.extant_block_ranges()?;
        trace!("cache has {:?}", extant);
        (_, remain) = remain.diff_inter(&extant);
        trace!(" .. after cache removal {remain:?}");

        // If it's in flight, don't request it again.
        let mut in_flight = RangeMap::new();
        for peer in self.peers.values() {
            for (_, start, end) in peer.pending_requests.values() {
                in_flight.with_range(&Range {
                    start: *start,
                    end: end + 1,
                });
            }
        }
        debug!("in_flight {in_flight:?}");
        (_, remain) = remain.diff_inter(&in_flight);

        let now = SystemTime::now();
        let failed_request_sleep_duration = self.failed_request_sleep_duration;
        debug!("after removing in_flight {:?}", remain);

        // If everything we have is in flight, we'll skip trying to request them (or update availability)
        if remain.is_empty() {
            trace!(" .. no non in_flight requests. Returning early");
            return Ok(true);
        }

        for chance in 0..2 {
            trace!(
                "chance = {chance} clock = {} peers = {}",
                self.clock,
                self.peers.len()
            );
            // There may be no peers ...
            self.clock = (self.clock + 1) % std::cmp::max(1, self.peers.len());
            // Slightly horrid - generate a list of peers which is the BTreeMap's list, shifted by clock.
            let peers = self
                .peers
                .keys()
                .skip(self.clock)
                .chain(self.peers.keys().take(self.clock))
                .cloned()
                .collect::<Vec<PeerId>>();

            for peer in &peers {
                debug!("peer = {peer}");
                // If the last request failed < 10s or so ago, skip this peer, unless we're second-chance in
                // which case, hey, why not?
                let (requests, rem, query_availability) = {
                    let peer_info = self.peer_info(*peer);
                    if chance == 0
                        && !peer_info
                            .last_request_failed_at
                            .and_then(|at| at.elapsed().ok())
                            .map(|time_since| time_since > failed_request_sleep_duration)
                            .unwrap_or(true)
                    {
                        trace!(".. Last request failed; skipping this peer");
                        continue;
                    }

                    // Split ..
                    let ranges = peer_info.get_ranges(to);
                    debug!("I want {remain:?} ({remain}) peer has ranges {ranges:?} ({ranges})");
                    let (req, rem) = remain.diff_inter(&ranges);
                    debug!("req {req:?} rem {rem:?}");
                    // If we are not about to make a request, and we do not have recent availability then
                    // make a synthetic request to get that availability.
                    let query_availability = req.is_empty()
                        && (!peer_info.have_availability()
                            || peer_info.availability_requested_at.map_or(true, |x| {
                                x.elapsed()
                                    .map(|v| {
                                        v > Duration::from_millis(
                                            constants::REQUEST_PEER_VIEW_AVAILABILITY_NOT_BEFORE_MS,
                                        )
                                    })
                                    .unwrap_or(true)
                            }));
                    (req, rem, query_availability)
                };

                let mut request_sent = false;
                debug!(" .. Requests to send: {:?}", requests);
                // Send all requests now ..
                for request in requests.ranges.iter() {
                    if !request.is_empty() {
                        trace!(
                            "peer = {:?} request = {:?} remains = {:?}: sending block request",
                            peer,
                            request,
                            requests
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
                            .insert(request_id, (now, request.start, request.end));
                        request_sent = true;
                    }
                }
                // If we haven't got recent availability, and we haven't already asked for it, ask ..
                if !request_sent && chance == 0 && query_availability {
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

                // We only need to request stuff from peers if we haven't already done so.
                remain = rem;
            }
        }
        trace!("All done");
        if !remain.is_empty() {
            warn!("Could not find peers for views {:?}", remain);
            if let Some(us) = &mut self.unserviceable_requests {
                us.with_range_map(&remain);
            } else {
                self.unserviceable_requests = Some(remain);
            }
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

        let result = if let Some((_, child)) = self
            .buffered
            .destructive_proposal_from_parent_hash(&block.hash())
        {
            Some(child)
        } else {
            None
        };

        self.highest_confirmed_view = std::cmp::max(self.highest_confirmed_view, block.header.view);
        // Trim the cache.
        self.buffered
            .trim(self.highest_confirmed_view, self.max_blocks_in_flight)?;

        Ok(result)
    }

    pub fn report_outgoing_message_failure(
        &mut self,
        failure: OutgoingMessageFailure,
    ) -> Result<()> {
        let peer_info = self.peer_info(failure.peer);
        let Some((_, from, to)) = peer_info.pending_requests.remove(&failure.request_id) else {
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
            NonZeroUsize::new(u64::try_into(self.max_blocks_in_flight).unwrap()).unwrap();
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

    pub fn next_proposal_if_likely(&mut self) -> Result<Option<(PeerId, Proposal)>> {
        if let Some(current_hash) = self.db.get_highest_block_hash()? {
            Ok(self
                .buffered
                .destructive_proposal_from_parent_hash(&current_hash))
        } else {
            Ok(None)
        }
    }
}
