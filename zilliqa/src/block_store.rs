use crate::message::ExternalMessage;
use std::{cell::RefCell, num::NonZeroUsize};

use anyhow::Result;
use lru::LruCache;
use sled::{Db, Tree};
use tracing::*;

use crate::{
    crypto::Hash,
    message::{Block, BlockRef, BlockRequest},
    node::MessageSender,
};

/// Stores and manages the node's list of blocks. Also responsible for making requests for new blocks. In the future,
/// this may become more complex with retries, batching, snapshots, etc.
#[derive(Debug)]
pub struct BlockStore {
    block_headers: Tree,
    canonical_block_numbers: Tree,
    blocks: Tree,
    block_cache: RefCell<LruCache<Hash, Block>>,
    message_sender: MessageSender,
}

impl BlockStore {
    pub fn new(db: &Db, message_sender: MessageSender) -> Result<Self> {
        Ok(BlockStore {
            block_headers: db.open_tree(b"block_headers_tree")?,
            canonical_block_numbers: db.open_tree(b"canonical_block_numbers_tree")?,
            blocks: db.open_tree(b"blocks_tree")?,
            block_cache: RefCell::new(LruCache::new(NonZeroUsize::new(5).unwrap())),
            message_sender,
        })
    }

    pub fn contains_block(&self, hash: Hash) -> Result<bool> {
        Ok(self.blocks.contains_key(hash.as_bytes())?)
    }

    pub fn get_block(&self, hash: Hash) -> Result<Option<Block>> {
        let mut block_cache = self.block_cache.borrow_mut();
        if let Some(block) = block_cache.get(&hash) {
            return Ok(Some(block.clone()));
        }
        let Some(block) = self.blocks.get(hash.as_bytes())? else {
            return Ok(None);
        };
        let block: Block = bincode::deserialize(&block)?;
        block_cache.put(hash, block.clone());
        Ok(Some(block))
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        let Some(hash) = self.canonical_block_numbers.get(view.to_be_bytes())? else {
            return Ok(None);
        };
        let hash = Hash::from_bytes(hash)?;
        self.get_block(hash)
    }

    pub fn request_block_by_view(&mut self, view: u64) -> Result<()> {
        trace!("Request block with view {view}");
        if let Some(hash) = self.canonical_block_numbers.get(view.to_be_bytes())? {
            let hash = Hash::from_bytes(hash)?;
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
        if !self.blocks.contains_key(hash.as_bytes())? {
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
        trace!(view = view, hash = ?hash, "set canonical block view");
        self.canonical_block_numbers
            .insert(view.to_be_bytes(), &hash.0)?;
        Ok(())
    }

    pub fn process_block(&mut self, block: Block) -> Result<()> {
        trace!(view = block.view(), hash = ?block.hash(), "insert block");
        self.block_headers
            .insert(block.hash().as_bytes(), bincode::serialize(&block.header)?)?;
        self.blocks
            .insert(block.hash().as_bytes(), bincode::serialize(&block)?)?;
        // TODO: Is this correct?
        self.set_canonical(block.view(), block.hash())?;
        Ok(())
    }
}
