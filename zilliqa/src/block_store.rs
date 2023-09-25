use crate::message::ExternalMessage;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use lru::LruCache;
use sled::{Db, Tree};
use tokio::{select, sync::Notify};
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
    block_cache: Mutex<LruCache<Hash, Block>>,
    message_sender: MessageSender,
    pending_requests: HashMap<BlockRef, Vec<Arc<Notify>>>,
    request_timeout: Duration,
}

impl BlockStore {
    pub fn new(db: &Db, message_sender: MessageSender) -> Result<Self> {
        Ok(BlockStore {
            block_headers: db.open_tree(b"block_headers_tree")?,
            canonical_block_numbers: db.open_tree(b"canonical_block_numbers_tree")?,
            blocks: db.open_tree(b"blocks_tree")?,
            block_cache: Mutex::new(LruCache::new(NonZeroUsize::new(5).unwrap())),
            message_sender,
            pending_requests: HashMap::new(),
            request_timeout: Duration::from_secs(2),
        })
    }

    /// Returns whether the block with the given hash is available locally.
    pub fn contains_block(&self, hash: Hash) -> Result<bool> {
        Ok(self.blocks.contains_key(hash.as_bytes())?)
    }

    /// Returns the block with the given hash. If it is not known locally,
    /// requests it from the network.
    /// Returns None if the network request times out.
    pub async fn get_block(&mut self, hash: Hash) -> Result<Option<Block>> {
        if !self.contains_block(hash)? {
            let timeout = self.request_timeout;
            let request = self.request_block(hash)?;
            // request.notified().await;
            select! {
                _ = request.notified() => {},
                _ = tokio::time::sleep(timeout) => {},
            }
        }
        self.get_block_locally(hash)
    }

    /// Sync function which only checks local storage, returning None if the block is not
    /// available.
    pub fn get_block_locally(&self, hash: Hash) -> Result<Option<Block>> {
        let mut block_cache = self.block_cache.lock().unwrap();
        if let Some(block) = block_cache.get(&hash) {
            return Ok(Some(block.clone()));
        }
        let Some(block) = self.blocks.get(hash.as_bytes())? else { return Ok(None); };
        let block: Block = bincode::deserialize(&block)?;
        block_cache.put(hash, block.clone());
        Ok(Some(block))
    }

    pub async fn get_hash_by_view(&mut self, view: u64) -> Result<Option<Hash>> {
        if !self
            .canonical_block_numbers
            .contains_key(view.to_be_bytes())?
        {
            let timeout = self.request_timeout;
            // self.request_hash_by_view(view).await;
            select! {
                _ = self.request_hash_by_view(view) => {},
                _ = tokio::time::sleep(timeout) => {},
            }
        }
        self.get_hash_by_view_locally(view)
    }

    pub fn get_hash_by_view_locally(&self, view: u64) -> Result<Option<Hash>> {
        self.canonical_block_numbers
            .get(view.to_be_bytes())?
            .map(Hash::from_bytes)
            .transpose()
    }

    pub async fn get_block_by_view(&mut self, view: u64) -> Result<Option<Block>> {
        let Some(hash) = self.get_hash_by_view(view).await? else { return Ok(None) };
        self.get_block(hash).await
    }

    pub fn get_block_by_view_locally(&self, view: u64) -> Result<Option<Block>> {
        let Some(hash) = self.get_hash_by_view_locally(view)? else { return Ok(None) };
        self.get_block_locally(hash)
    }

    /// Helper method to create and store the Notify for when the request completes,
    /// and returns a copy locally awaiting
    fn register_request(&mut self, key: BlockRef) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        if let Some(notifies) = self.pending_requests.get_mut(&key) {
            notifies.push(notify.clone());
        } else {
            self.pending_requests.insert(key, vec![notify.clone()]);
        }
        notify
    }

    /// Helper function to create an already-resolved notify.
    /// Simplifies handling of block requests when we already have the block locally.
    fn noop_notify() -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        notify.notify_one();
        notify
    }

    /// Sends a network request for the block with the given hash.
    /// No-op if the block is already known locally.
    /// Returns a Notify which can be waited on (with `.notified().await`) if
    /// you need to block on the result. It can also be safely dropped.
    pub fn request_block(&mut self, hash: Hash) -> Result<Arc<Notify>> {
        if !self.blocks.contains_key(hash.as_bytes())? {
            let block_ref = BlockRef::Hash(hash);
            self.message_sender
                .broadcast_external_message(ExternalMessage::BlockRequest(BlockRequest(block_ref)))
                .unwrap();
            Ok(self.register_request(block_ref))
        } else {
            trace!("Already got the block with hash {hash}");
            Ok(Self::noop_notify())
        }
    }

    /// Sends a network request for the hash of the block with the given view.
    /// No-op if the hash is already known locally.
    /// Returns a Notify which can be waited on (with `.notified().await`) if
    /// you need to block on the result. It can also be safely dropped.
    pub async fn request_hash_by_view(&mut self, view: u64) -> Result<Arc<Notify>> {
        if !self
            .canonical_block_numbers
            .contains_key(view.to_be_bytes())?
        {
            // TODO: implement hash request message, to avoid having to request the entire block
            self.request_block_by_view(view)
        } else {
            Ok(Self::noop_notify())
        }
    }

    /// Sends a network request for the block with the given height.
    /// No-op if the block is already known locally.
    /// Returns a Notify which can be waited on (with `.notified().await`) if
    /// you need to block on the result. It can also be safely dropped.
    pub fn request_block_by_view(&mut self, view: u64) -> Result<Arc<Notify>> {
        trace!("Request block with view {view}");
        if let Some(hash) = self.canonical_block_numbers.get(view.to_be_bytes())? {
            let hash = Hash::from_bytes(hash)?;
            trace!("I know the hash, its {hash}");
            self.request_block(hash)
        } else {
            trace!("I don't know the hash");
            let block_ref = BlockRef::View(view);
            self.message_sender
                .broadcast_external_message(ExternalMessage::BlockRequest(BlockRequest(block_ref)))
                .unwrap();
            Ok(self.register_request(block_ref))
        }
    }

    pub fn set_canonical(&mut self, view: u64, hash: Hash) -> Result<()> {
        self.canonical_block_numbers
            .insert(view.to_be_bytes(), &hash.0)?;
        Ok(())
    }

    /// Permanently stores a block.
    /// Additionally resolves any futures that were pending on a request for this block.
    pub fn process_block(&mut self, block: Block) -> Result<()> {
        trace!(view = block.view(), hash = ?block.hash(), "insert block");
        self.block_headers
            .insert(block.hash().as_bytes(), bincode::serialize(&block.header)?)?;
        self.blocks
            .insert(block.hash().as_bytes(), bincode::serialize(&block)?)?;
        // TODO: Is this correct?
        self.set_canonical(block.view(), block.hash())?;
        for notify in self
            .pending_requests
            .remove(&BlockRef::Hash(block.hash()))
            .unwrap_or_default()
            .into_iter()
            .chain(
                self.pending_requests
                    .remove(&BlockRef::View(block.view()))
                    .unwrap_or_default()
                    .into_iter(),
            )
        {
            notify.notify_one();
            // we know we were requesting this block so put it into the cache for immediate access
            self.block_cache
                .lock()
                .unwrap()
                .put(block.hash(), block.clone());
        }
        Ok(())
    }
}
