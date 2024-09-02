use std::{
    cmp,
    collections::{BTreeSet, HashMap},
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
    peers: HashMap<PeerId, PeerInfo>,
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
    unserviceable_requests: BTreeSet<(u64, u64)>,
    message_sender: MessageSender,
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
    /// The number of blocks we've requested from the peer.
    requested_blocks: u64,
    /// Requests we've sent to the peer.
    pending_requests: LruCache<RequestId, (u64, u64)>,
    /// If `Some`, the time of the most recently failed request.
    last_request_failed_at: Option<SystemTime>,
}

impl PeerInfo {
    fn new(request_capacity: NonZeroUsize) -> Self {
        Self {
            availability: BlockAvailability::new(),
            availability_updated_at: None,
            requested_blocks: 0,
            pending_requests: LruCache::new(request_capacity),
            last_request_failed_at: None,
        }
    }
}

/// Data about a peer
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerInfoStatus {
    availability: BlockAvailability,
    availability_updated_at: Option<u64>,
    requested_blocks: u64,
    pending_requests: Vec<(String, u64, u64)>,
    last_request_failed_at: Option<u64>,
}

/// Data about the block store, used for debugging.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockStoreStatus {
    highest_known_view: u64,
    blocks_held: Vec<Range<u64>>,
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
            blocks_held: block_store.db.get_block_ranges()?,
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
            .map(|(k, v)| (format!("{:?}", k), v.0, v.1))
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
            peers: HashMap::new(),
            requested_view: 0,
            max_blocks_in_flight: config.max_blocks_in_flight,
            batch_size: config.block_request_batch_size,
            failed_request_sleep_duration: config.failed_request_sleep_duration,
            strategies: vec![],
            available_blocks: vec![],
            available_blocks_updated: None,
            buffered: LruCache::new(
                NonZeroUsize::new(config.max_blocks_in_flight as usize + 100).unwrap(),
            ),
            unserviceable_requests: BTreeSet::new(),
            message_sender,
        })
    }

    /// Create a read-only clone of this [BlockStore]. The read-only property must be upheld by the caller - Calling
    /// any `&mut self` methods on the returned [BlockStore] will lead to problems. This clone is cheap.
    pub fn clone_read_only(&self) -> Arc<Self> {
        Arc::new(BlockStore {
            db: self.db.clone(),
            block_cache: self.block_cache.clone(),
            highest_known_view: 0,
            peers: HashMap::new(),
            requested_view: 0,
            max_blocks_in_flight: 0,
            batch_size: 0,
            failed_request_sleep_duration: Duration::ZERO,
            strategies: self.strategies.clone(),
            available_blocks: Vec::new(),
            available_blocks_updated: None,
            buffered: LruCache::new(NonZeroUsize::new(1).unwrap()),
            unserviceable_requests: BTreeSet::new(),
            message_sender: self.message_sender.clone(),
        })
    }

    /// Update someone else's availability
    pub fn update_availability(
        &mut self,
        from: PeerId,
        avail: &Option<Vec<BlockStrategy>>,
    ) -> Result<()> {
        let the_peer = self.peer_info(from);
        the_peer.availability.strategies = avail.clone();
        the_peer.availability_updated_at = Some(SystemTime::now());
        Ok(())
    }

    /// Retrieve our availability.
    pub fn availability(&mut self) -> Result<Option<Vec<BlockStrategy>>> {
        let mut to_return = self.strategies.clone();
        let now = SystemTime::now();
        if self.available_blocks_updated.map_or(false, |x| {
            now.duration_since(x).unwrap_or(Duration::ZERO)
                > Duration::from_secs(constants::RECOMPUTE_BLOCK_AVAILABILITY_AFTER_S)
        }) {
            trace!("Updating available blocks");
            self.available_blocks = self
                .db
                .get_block_ranges()?
                .iter()
                .map(|x| BlockStrategy::CachedBlockRange(x.clone(), 0))
                .collect();
            self.available_blocks_updated = Some(now);
        }
        to_return.extend(self.available_blocks.iter().map(|x| x.clone()));
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

    pub fn request_missing_blocks(&mut self) -> Result<()> {
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

        // Attempt to send pending requests if we can.
        while let Some((from, to)) = self.unserviceable_requests.pop_first() {
            if !self.request_blocks(from, to)? {
                // Stop trying to send requests if no peers are available.
                break;
            }
        }

        // If we think the network might be ahead of where we currently are, attempt to download the missing blocks.
        if self.highest_known_view > current_view {
            trace!(
                current_view,
                self.highest_known_view,
                self.requested_view,
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
                self.request_blocks(from, to)?;
            }
        }

        Ok(())
    }

    /// Make a request for a range of blocks. Returns `true` if a request was made and `false` if the request had to be
    /// buffered because no peers were available.
    fn request_blocks(&mut self, from: u64, to: u64) -> Result<bool> {
        let Some(peer) = self.best_peer(from) else {
            warn!(from, "no peers to download missing blocks from");
            self.unserviceable_requests.insert((from, to));
            return Ok(false);
        };
        trace!(%peer, from, to, "requesting blocks");
        let message = ExternalMessage::BlockRequest(BlockRequest {
            from_view: from,
            to_view: to,
        });
        let request_id = self.message_sender.send_external_message(peer, message)?;

        let peer_info = self.peer_info(peer);
        peer_info.requested_blocks += to - from + 1;
        peer_info.pending_requests.put(request_id, (from, to));
        self.requested_view = to;

        Ok(true)
    }

    pub fn contains_block(&self, hash: Hash) -> Result<bool> {
        self.db.contains_block(&hash)
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
        let Some((from, to)) = peer_info.pending_requests.pop(&failure.request_id) else {
            // A request we didn't know about failed. It must have been sent by someone else.
            return Ok(());
        };
        peer_info.last_request_failed_at = Some(SystemTime::now());

        self.request_blocks(from, to)?;

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
}
