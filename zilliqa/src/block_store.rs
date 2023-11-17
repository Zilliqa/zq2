use crate::message::ExternalMessage;
use std::{cell::RefCell, num::NonZeroUsize, sync::Arc};

use anyhow::Result;
use libp2p::PeerId;
use lru::LruCache;
use tracing::*;

use crate::{
    crypto::Hash,
    db::Db,
    message::{Block, BlockBatchRequest, BlockRef, BlockRequest},
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
        let Some(block) = self.db.get_block(&hash)? else {
            return Ok(None);
        };
        block_cache.put(hash, block.clone());
        Ok(Some(block))
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        let Some(hash) = self.db.get_canonical_block_view(view)? else {
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

    pub fn request_block_by_view(&mut self, view: u64) -> Result<()> {
        if let Some(hash) = self.db.get_canonical_block_view(view)? {
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
        if let Some(hash) = self.db.get_canonical_block_number(number)? {
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

    pub fn request_blocks(&mut self, peer: Option<PeerId>, number: u64) -> Result<()> {

        // If the request is higher than our head, lower it to our head, as we don't store
        // loose blocks
        let number = std::cmp::min(number, self.db.get_highest_block_number().unwrap().unwrap());

        let request =
            ExternalMessage::BlockBatchRequest(BlockBatchRequest(BlockRef::Number(number)));

        // We can request blocks from a single peer or from all peers.
        match peer {
            Some(peer) => {
                self.message_sender
                    .send_external_message(peer, request)
                    .unwrap();
            }
            None => {
                self.message_sender
                    .broadcast_external_message(request)
                    .unwrap();
            }
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

    pub fn set_canonical(&mut self, number: u64, view: u64, hash: Hash) -> Result<()> {
        self.db.put_canonical_block_view(view, hash)?;
        self.db.put_canonical_block_number(number, hash)?;
        Ok(())
    }

    pub fn process_block(&mut self, block: Block) -> Result<()> {
        trace!(number = block.number(), hash = ?block.hash(), "insert block");
        self.db.insert_block_header(&block.hash(), &block.header)?;
        self.db.insert_block(&block.hash(), &block)?;
        // TODO: Is this correct?
        self.set_canonical(block.number(), block.view(), block.hash())?;
        Ok(())
    }
}
