use crate::message::ExternalMessage;
use std::{cell::RefCell, num::NonZeroUsize};

use anyhow::Result;
use lru::LruCache;
use sled::{Db, Tree};
use tracing::*;

use crate::{
    crypto::Hash,
    message::{Block, BlockRef, BlockRequest, BlocksRequest, QuorumCertificate},
    node::MessageSender,
};

/// Stores and manages the node's list of blocks. Also responsible for making requests for new blocks. In the future,
/// this may become more complex with retries, batching, snapshots, etc.
#[derive(Debug)]
pub struct BlockStore {
    block_headers: Tree,
    canonical_block_numbers: Tree,
    canonical_block_views: Tree,
    blocks: Tree,
    high_qc: Tree,
    block_cache: RefCell<LruCache<Hash, Block>>,
    message_sender: MessageSender,
}

impl BlockStore {
    pub fn new(db: &Db, message_sender: MessageSender) -> Result<Self> {
        Ok(BlockStore {
            block_headers: db.open_tree(b"block_headers_tree")?,
            canonical_block_numbers: db.open_tree(b"canonical_block_numbers_tree")?,
            canonical_block_views: db.open_tree(b"canonical_block_views_tree")?,
            blocks: db.open_tree(b"blocks_tree")?,
            high_qc: db.open_tree(b"high_qc_tree")?,
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
        let Some(hash) = self.canonical_block_views.get(view.to_be_bytes())? else {
            return Ok(None);
        };
        let hash = Hash::from_bytes(hash)?;
        self.get_block(hash)
    }

    pub fn get_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        let Some(hash) = self.canonical_block_numbers.get(number.to_be_bytes())? else {
            return Ok(None);
        };
        let hash = Hash::from_bytes(hash)?;
        self.get_block(hash)
    }

    pub fn request_block_by_view(&mut self, view: u64) -> Result<()> {
        if let Some(hash) = self.canonical_block_views.get(view.to_be_bytes())? {
            let hash = Hash::from_bytes(hash)?;
            self.request_block(hash)?;
        } else {
            self.message_sender
                .broadcast_external_message(ExternalMessage::BlockRequest(BlockRequest(
                    BlockRef::View(view),
                )))
                .unwrap();
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn request_block_by_number(&mut self, number: u64) -> Result<()> {
        if let Some(hash) = self.canonical_block_numbers.get(number.to_be_bytes())? {
            let hash = Hash::from_bytes(hash)?;
            self.request_block(hash)?;
        } else {
            self.message_sender
                .broadcast_external_message(ExternalMessage::BlockRequest(BlockRequest(
                    BlockRef::Number(number),
                )))
                .unwrap();
        }
        Ok(())
    }

    pub fn request_blocks(&mut self, number: u64) -> Result<()> {
        self.message_sender
            .broadcast_external_message(ExternalMessage::BlocksRequest(BlocksRequest(
                BlockRef::Number(number),
            )))
            .unwrap();

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

    pub fn set_canonical(&mut self, number: u64, view: u64, hash: Hash) -> Result<()> {
        self.canonical_block_numbers
            .insert(number.to_be_bytes(), &hash.0)?;
        self.canonical_block_views
            .insert(view.to_be_bytes(), &hash.0)?;

        Ok(())
    }

    pub fn set_high_qc(&mut self, high_qc: QuorumCertificate) -> Result<()> {
        self.high_qc
            .insert("".as_bytes(), bincode::serialize(&high_qc)?)?;

        Ok(())
    }

    pub fn get_high_qc(&mut self) -> Result<Option<QuorumCertificate>> {
        let Some(result) = self.high_qc.get("".as_bytes())? else {
            return Ok(None);
        };

        let result: QuorumCertificate = bincode::deserialize(&result)?;
        Ok(Some(result))
    }

    pub fn process_block(&mut self, block: Block) -> Result<()> {
        trace!(number = block.number(), hash = ?block.hash(), "insert block");
        self.block_headers
            .insert(block.hash().as_bytes(), bincode::serialize(&block.header)?)?;
        self.blocks
            .insert(block.hash().as_bytes(), bincode::serialize(&block)?)?;
        // TODO: Is this correct?
        self.set_canonical(block.number(), block.view(), block.hash())?;
        Ok(())
    }
}
