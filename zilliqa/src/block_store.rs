use std::{cell::RefCell, num::NonZeroUsize, sync::Arc};

use anyhow::{anyhow, Result};
use libp2p::PeerId;
use lru::LruCache;
use tracing::*;

use crate::{
    cfg::NodeConfig,
    crypto::Hash,
    db::Db,
    message::{Block, BlockRequest, ExternalMessage, Proposal},
    node::MessageSender,
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
    block_cache: RefCell<LruCache<Hash, Block>>,
    /// The maximum view of any proposal we have received, even if it is not part of our chain yet.
    highest_known_view: u64,
    /// The maximum view of blocks we've sent a request for.
    requested_view: u64,
    /// The maximum number of blocks to send requests for at a time.
    max_blocks_in_flight: u64,
    /// The maximum number of blocks to request at a time.
    batch_size: u64,
    /// Buffered block proposals, indexed by their parent hash. These are proposals we've received, whose parents we
    /// haven't yet seen. We want to be careful about buffering too many proposals. There is no guarantee or proof that
    /// any of them will eventually form our canonical chain. Therefore we limit the number of buffered proposals to
    /// `max_blocks_in_flight + 100`. This number is chosen because it makes it probable we will always be able to
    /// handle pending requests made by ourselves that arrive out-of-order, while also giving some extra space for
    /// newly created blocks that arrive while we are syncing.
    buffered: LruCache<Hash, Proposal>,
    message_sender: MessageSender,
}

impl BlockStore {
    pub fn new(config: &NodeConfig, db: Arc<Db>, message_sender: MessageSender) -> Result<Self> {
        Ok(BlockStore {
            db,
            block_cache: RefCell::new(LruCache::new(NonZeroUsize::new(5).unwrap())),
            highest_known_view: 0,
            requested_view: 0,
            max_blocks_in_flight: config.max_blocks_in_flight,
            batch_size: config.block_request_batch_size,
            buffered: LruCache::new(
                NonZeroUsize::new(config.max_blocks_in_flight as usize + 100).unwrap(),
            ),
            message_sender,
        })
    }

    /// Buffer a block proposal whose parent we don't yet know about.
    pub fn buffer_proposal(
        &mut self,
        proposal: Proposal,
        random_peer: Option<PeerId>,
    ) -> Result<()> {
        let view = proposal.view();

        self.buffered.push(proposal.header.parent_hash, proposal);

        // If this is the highest block we've seen, remember its view.
        if view > self.highest_known_view {
            trace!(view, "new highest known view");
            self.highest_known_view = view;
        }

        self.request_missing_blocks(random_peer)?;

        Ok(())
    }

    pub fn request_missing_blocks(&mut self, random_peer: Option<PeerId>) -> Result<()> {
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

        // If we think the network might be ahead of where we currently are, attempt to download the missing blocks.
        if self.highest_known_view > current_view {
            trace!(current_view, self.highest_known_view, "missing some blocks");
            // The first condition checks that there are more blocks we haven't requested yet. The second condition
            // ensures that we respect our `max_blocks_in_flight` parameter. Note that we subtract the configured
            // `batch_size` from this to ensure our new requests don't overlap with previous in-flight requests.
            while self.requested_view < self.highest_known_view
                && (self.requested_view - current_view)
                    <= (self.max_blocks_in_flight - self.batch_size)
            {
                trace!(
                    from = self.requested_view + 1,
                    to = self.requested_view + self.batch_size,
                    "requesting blocks"
                );
                let message = ExternalMessage::BlockRequest(BlockRequest {
                    from_view: self.requested_view + 1,
                    to_view: self.requested_view + self.batch_size,
                });
                if let Some(random_peer) = random_peer {
                    self.message_sender
                        .send_external_message(random_peer, message)?;
                } else {
                    self.message_sender.broadcast_external_message(message)?;
                }
                self.requested_view += self.batch_size;
            }
        }

        Ok(())
    }

    pub fn contains_block(&self, hash: Hash) -> Result<bool> {
        self.db.contains_block(&hash)
    }

    pub fn get_block(&self, hash: Hash) -> Result<Option<Block>> {
        let mut block_cache = self.block_cache.borrow_mut();
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

    pub fn get_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        let Some(hash) = self.db.get_canonical_block_number(number)? else {
            return Ok(None);
        };
        self.get_block(hash)
    }

    pub fn process_block(&mut self, block: Block) -> Result<Option<Proposal>> {
        trace!(number = block.number(), hash = ?block.hash(), "insert block");
        self.db.insert_block(&block)?;
        self.db
            .put_canonical_block_number(block.number(), block.hash())?;

        if let Some(child) = self.buffered.pop(&block.hash()) {
            return Ok(Some(child));
        }

        Ok(None)
    }
}
