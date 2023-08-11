use crate::message::ExternalMessage;
use std::{cell::RefCell, num::NonZeroUsize, sync::Arc};

use anyhow::Result;
use lru::LruCache;
use tracing::*;

use crate::{
    crypto::Hash,
    db::Db,
    message::{Block, BlockRef, BlockRequest},
    node::MessageSender,
};

/// Stores and manages the node's list of blocks. Also responsible for making requests for new blocks. In the future,
/// this may become more complex with retries, batching, snapshots, etc.
#[derive(Debug)]
pub struct BlockStore {
    db: Arc<Db>,
    block_cache: RefCell<LruCache<Hash, Block>>,
    message_sender: MessageSender,
}

impl BlockStore {
    pub fn new(db: Arc<Db>, message_sender: MessageSender) -> Result<Self> {
        Ok(BlockStore {
            db,
            block_cache: RefCell::new(LruCache::new(NonZeroUsize::new(5).unwrap())),
            message_sender,
        })
    }

    pub fn contains_block(&self, hash: Hash) -> Result<bool> {
        self.db.contains_block(&hash)
    }

    pub fn get_block(&self, hash: Hash) -> Result<Option<Block>> {
        let mut block_cache = self.block_cache.borrow_mut();
        if let Some(block) = block_cache.get(&hash) {
            return Ok(Some(block.clone()));
        }
        let Some(block) = self.db.get_block(&hash)? else { return Ok(None); };
        block_cache.put(hash, block.clone());
        Ok(Some(block))
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        let Some(hash) = self.db.get_canonical_block_number(view)? else { return Ok(None); };
        self.get_block(hash)
    }

    pub fn request_block_by_view(&mut self, view: u64) -> Result<()> {
        trace!("Request block with view {view}");
        if let Some(hash) = self.db.get_canonical_block_number(view)? {
            trace!("I know the hash, its {hash}");
            self.request_block(hash)?;
        } else {
            trace!("I don't know the hash");
            self.message_sender
                .broadcast_external_message(ExternalMessage::BlockRequest(BlockRequest(
                    BlockRef::View(view),
                )))
                .unwrap();
        }
        Ok(())
    }

    pub fn request_block(&mut self, hash: Hash) -> Result<()> {
        if !self.db.contains_block(&hash)? {
            self.message_sender
                .broadcast_external_message(ExternalMessage::BlockRequest(BlockRequest(
                    BlockRef::Hash(hash),
                )))
                .unwrap();
        } else {
            trace!("Already got the block with hash {hash}");
        }
        Ok(())
    }

    pub fn set_canonical(&mut self, view: u64, hash: Hash) -> Result<()> {
        self.db.put_canonical_block_number(view, hash)?;
        Ok(())
    }

    pub fn process_block(&mut self, block: Block) -> Result<()> {
        trace!(view = block.view(), hash = ?block.hash(), "insert block");
        self.db.insert_block_header(&block.hash(), &block.header)?;
        self.db.insert_block(&block.hash(), &block)?;
        // TODO: Is this correct?
        self.set_canonical(block.view(), block.hash())?;
        Ok(())
    }
}
