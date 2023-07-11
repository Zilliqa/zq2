use std::collections::BTreeMap;

use libp2p::PeerId;
use tokio::sync::mpsc::UnboundedSender;
use tracing::trace;

use crate::{
    crypto::Hash,
    message::{Block, BlockRef, BlockRequest, Message},
};

/// Stores and manages the node's list of blocks. Also responsible for making requests for new blocks. In the future,
/// this may become more complex with retries, batching, snapshots, etc.
#[derive(Debug)]
pub struct BlockStore {
    view_to_block_hash: BTreeMap<u64, Hash>,
    blocks: BTreeMap<Hash, Block>,
    message_sender: UnboundedSender<(Option<PeerId>, Message)>,
}

impl BlockStore {
    pub fn new(message_sender: UnboundedSender<(Option<PeerId>, Message)>) -> Self {
        BlockStore {
            view_to_block_hash: BTreeMap::new(),
            blocks: BTreeMap::new(),
            message_sender,
        }
    }

    pub fn contains_block(&self, hash: Hash) -> bool {
        self.blocks.contains_key(&hash)
    }

    pub fn get_block(&self, hash: Hash) -> Option<&Block> {
        self.blocks.get(&hash)
    }

    pub fn get_block_by_view(&self, view: u64) -> Option<&Block> {
        self.view_to_block_hash
            .get(&view)
            .and_then(|hash| self.get_block(*hash))
    }

    pub fn request_block_by_view(&self, view: u64) {
        trace!("Request block with view {view}");
        if let Some(hash) = self.view_to_block_hash.get(&view) {
            trace!("I know the hash, its {hash}");
            self.request_block(*hash);
        } else {
            trace!("I don't know the hash");
            self.message_sender
                .send((
                    None,
                    Message::BlockRequest(BlockRequest(BlockRef::View(view))),
                ))
                .unwrap();
        }
        trace!(
            "Block views I know: {:?}",
            self.view_to_block_hash.keys().collect::<Vec<_>>()
        );
    }

    pub fn request_block(&self, hash: Hash) {
        if !self.blocks.contains_key(&hash) {
            self.message_sender
                .send((
                    None,
                    Message::BlockRequest(BlockRequest(BlockRef::Hash(hash))),
                ))
                .unwrap();
        } else {
            trace!("Already got the block with hash {hash}");
        }
    }

    pub fn process_block(&mut self, block: Block) {
        trace!(view = block.view(), hash = ?block.hash(), "insert block");
        self.view_to_block_hash.insert(block.view(), block.hash());
        self.blocks.insert(block.hash(), block);
    }
}
