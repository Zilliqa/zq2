use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::crypto::Hash;
use anyhow::Result;
use itertools::Itertools;
use libp2p::PeerId;

use crate::{
    cfg::NodeConfig,
    db::Db,
    message::{
        Block, ChainMetaData, ExternalMessage, InjectedProposal, Proposal, RequestBlock,
        ResponseBlock,
    },
    node::MessageSender,
};

enum DownGrade {
    None,
    Partial,
    Timeout,
    Empty,
}

// Syncing Algorithm
//
// When a Proposal is received by Consensus, we check if the parent exists in our DB.
// If not, then it triggers a syncing algorithm.
//
// 1. We check if the gap between our last canonical block and the latest Proposal.
//     a. If it is a small gap, we request for blocks, going backwards from Proposal.
//     b. If it is a big gap, we request for blocks, going forwards from Canonical.
// 2. When we receive a forwards history response, we check for matches against the cache.
//    This means that for a proposal to be injected, it must be corroborated by 2 sources.
//     a. If it matches the cached value, we inject the proposal into the pipeline.
//     b. If it does not match, we replace the cached value and request for more.
//     b. If it does not exist in the cache, we cache the proposal.
// 3. When we receive a backwards history response, we inject it into the pipeline.
//     a. If it does not line up with the existing Canonical, then it will be dropped.
//
// TODO: How to handle case where only single source of truth i.e. bootstrap node?

const GAP_THRESHOLD: usize = 5; // How big is big/small gap.
const DO_SPECULATIVE: bool = false; // Speeds up syncing by speculatively fetching blocks, allowing it to catch up.

#[derive(Debug)]
pub struct BlockStore {
    // database
    db: Arc<Db>,
    // message bus
    message_sender: MessageSender,
    // internal peers
    peers: BinaryHeap<PeerInfo>,
    // in-flight
    in_flight: Option<PeerInfo>,
    // in-flight timeout
    request_timeout: Duration,
    // how many blocks to request at once
    max_batch_size: usize,
    // how many blocks to inject into the queue
    max_blocks_in_flight: usize,
    // our peer id
    peer_id: PeerId,
    // how many injected proposals
    injected: usize,
    // cache
    cache: HashMap<u64, Proposal>,
    latest_block: Option<Block>,

    // Chain metadata
    chain_metadata: BTreeMap<Hash, ChainMetaData>,
    p1_metadata: Option<ChainMetaData>,
    p2_metadata: Option<ChainMetaData>,
    landmarks: Vec<Hash>,
}

impl BlockStore {
    pub fn new(
        config: &NodeConfig,
        db: Arc<Db>,
        message_sender: MessageSender,
        peers: Vec<PeerId>,
    ) -> Result<Self> {
        let peers = peers
            .into_iter()
            .map(|peer_id| PeerInfo {
                score: 0,
                peer_id,
                last_used: Instant::now(),
            })
            .collect();
        let peer_id = message_sender.our_peer_id;

        Ok(Self {
            db,
            message_sender,
            peers,
            peer_id,
            request_timeout: config.consensus.consensus_timeout,
            max_batch_size: config.block_request_batch_size.max(31), // between 30 seconds and 3 days of blocks.
            max_blocks_in_flight: config.max_blocks_in_flight.min(3600), // cap to 1-hr worth of blocks
            in_flight: None,
            injected: 0,
            cache: HashMap::new(),
            latest_block: None,
            chain_metadata: BTreeMap::new(),
            p1_metadata: None,
            landmarks: Vec::new(),
            p2_metadata: None,
        })
    }

    /// Mark a received proposal
    ///
    /// Mark a proposal as received, and remove it from the cache.
    pub fn mark_received_proposal(&mut self, prop: &InjectedProposal) -> Result<()> {
        if prop.from != self.peer_id {
            tracing::error!(
                "blockstore::MarkReceivedProposal : foreign InjectedProposal from {}",
                prop.from
            );
        }
        if let Some(p) = self.cache.remove(&prop.block.number()) {
            tracing::warn!(
                "blockstore::MarkReceivedProposal : removing stale cache proposal {}",
                p.number()
            );
        }
        self.injected = self.injected.saturating_sub(1);
        Ok(())
    }

    /// Process a block proposal.
    /// Checks if the parent block exists, and if not, triggers a sync.
    pub fn process_proposal(&mut self, block: Block) -> Result<()> {
        // ...
        // check if block parent exists
        let parent_block = self.db.get_block_by_hash(&block.parent_hash())?;

        // no parent block, trigger sync
        if parent_block.is_none() {
            tracing::warn!(
                "blockstore::ProcessProposal : Parent block {} not found",
                block.parent_hash()
            );
            if self.p2_metadata.is_some() {
                // Continue phase 2
                self.request_missing_blocks()?;
            } else {
                if self.p1_metadata.is_none() {
                    // Start phase 1
                    self.request_missing_chain(Some(block))?;
                } else {
                    // Continue phase 1
                    self.request_missing_chain(None)?;
                }
            }
            return Ok(());
        }
        Ok(())
    }

    /// Convenience function to convert a block to a proposal (add full txs)
    /// NOTE: Includes intershard transactions. Should only be used for syncing history,
    /// not for consensus messages regarding new blocks.
    fn block_to_proposal(&self, block: Block) -> Proposal {
        // since block must be valid, unwrap(s) are safe
        let txs = block
            .transactions
            .iter()
            .map(|hash| self.db.get_transaction(hash).unwrap().unwrap())
            .map(|tx| tx.verify().unwrap())
            .collect_vec();

        Proposal::from_parts(block, txs)
    }

    /// Convenience function to extract metadata from the block.
    fn block_to_metadata(&self, block: Block) -> ChainMetaData {
        ChainMetaData {
            block_number: block.number(),
            block_hash: block.hash(),
            parent_hash: block.parent_hash(),
            block_timestamp: block.timestamp(),
        }
    }

    /// Handle a multi-block response.
    ///
    /// This is the final step in the syncing algorithm, where we receive a set of blocks and inject them into
    /// the pipeline. We also remove the blocks from the chain metadata, because they are now in the pipeline.
    pub fn handle_multiblock_response(
        &mut self,
        from: PeerId,
        response: Vec<Proposal>,
    ) -> Result<()> {
        // ...
        tracing::info!(
            "blockstore::MultiBlockResponse : received {} blocks from {}",
            response.len(),
            from
        );

        // Process whatever we received
        if response.is_empty() {
            // Empty response, downgrade peer
            tracing::warn!("blockstore::MultiBlockResponse : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
        } else if response.len() < self.max_batch_size {
            // Partial response, downgrade peer
            tracing::warn!("blockstore::MultiBlockResponse : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        let proposals = response
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        if let Some(landmark) = self.landmarks.pop() {
            // remove the last landmark, should match proposals.last()
            let hash = proposals.last().as_ref().unwrap().hash();
            if hash != landmark {
                tracing::warn!(
                    "blockstore::MultiBlockResponse : mismatched landmark {} != {}",
                    landmark,
                    hash,
                );
                self.landmarks.push(landmark); // put it back
            }
        }

        // Remove the blocks from the chain metadata, if they exist
        for p in &proposals {
            self.chain_metadata.remove(&p.hash());
        }

        self.inject_proposals(proposals)?;

        // Done with phase 2, allow phase 1 to restart.
        if self.landmarks.is_empty() {
            self.p1_metadata = None;
            self.chain_metadata.clear();
        } else if DO_SPECULATIVE {
            // Speculatively request more blocks
            self.request_missing_blocks()?;
        }

        Ok(())
    }

    pub fn handle_multiblock_request(
        &mut self,
        from: PeerId,
        request: Vec<Hash>,
    ) -> Result<ExternalMessage> {
        // ...
        tracing::info!(
            "blockstore::MultiBlockRequest : received a {} multiblock request from {}",
            request.len(),
            from
        );

        let batch_size: usize = self.max_batch_size.min(request.len()); // mitigate DOS by limiting the number of blocks we return
        let mut proposals = Vec::with_capacity(batch_size);
        for hash in request {
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            proposals.push(self.block_to_proposal(block));
        }

        let message = ExternalMessage::MultiBlockResponse(proposals);
        Ok(message)
    }

    /// Request missing blocks from the chain.
    ///
    /// It constructs a set of hashes, which constitute the series of blocks that are missing.
    /// These hashes are then sent to a Peer for retrieval.
    /// This is Part 2 of the syncing algorithm.
    fn request_missing_blocks(&mut self) -> Result<()> {
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "blockstore::RequestMissingBlocks : in-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.done_with_peer(DownGrade::Timeout);
            } else {
                return Ok(());
            }
        } else {
            if self.p2_metadata.is_none() {
                tracing::warn!(
                    "blockstore::RequestMissingBlocks : no metadata to request missing blocks"
                );
                return Ok(());
            }
        }

        if let Some(peer) = self.get_next_peer() {
            // If we have no landmarks, we have nothing to do
            self.p2_metadata = None;
            if let Some(mut hash) = self.landmarks.pop() {
                self.landmarks.push(hash); // we actually need to peek() at the last element
                let mut request_hashes = Vec::with_capacity(self.max_batch_size);
                while let Some(meta) = self.chain_metadata.remove(&hash) {
                    request_hashes.push(meta.block_hash);
                    hash = meta.parent_hash;
                    // re-insert the metadata so as not to lose it
                    // self.chain_metadata.insert(hash, meta);
                    self.p2_metadata = Some(meta);
                }

                // Fire request
                tracing::debug!(
                    "blockstore::RequestMissingBlocks : requesting {} blocks of set #{}",
                    request_hashes.len(),
                    self.landmarks.len(),
                );
                self.message_sender.send_external_message(
                    peer.peer_id,
                    ExternalMessage::MultiBlockRequest(request_hashes),
                )?;
                self.in_flight = Some(peer);
            } else {
                // No more landmarks, we're done
                self.peers.push(peer);
            }
        } else {
            tracing::warn!(
                "blockstore::RequestMissingBlocks : insufficient peers to request missing blocks"
            );
        }
        Ok(())
    }

    /// Handle a response to a metadata request.
    ///
    /// This is the first step in the syncing algorithm, where we receive a set of metadata and use it to
    /// construct a chain history. We then request the missing blocks from the chain.
    pub fn handle_metadata_response(
        &mut self,
        from: PeerId,
        response: Vec<ChainMetaData>,
    ) -> Result<()> {
        tracing::info!(
            "blockstore::MetadataResponse : received {} metadata from {}",
            response.len(),
            from
        );

        // Process whatever we have received.
        if response.is_empty() {
            // Empty response, downgrade peer
            tracing::warn!("blockstore::MetadataResponse : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else if response.len() < self.max_batch_size {
            // Partial response, downgrade peer
            tracing::warn!("blockstore::MetadataResponse : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        // Sort metadata by number, reversed
        let metadata = response
            .into_iter()
            .sorted_by(|a, b| b.block_number.cmp(&a.block_number))
            .collect_vec();

        let p1_metadata = metadata.last().unwrap().clone();
        let last_hash = p1_metadata.block_hash;
        self.p1_metadata = Some(p1_metadata);

        self.landmarks
            .push(metadata.first().as_ref().unwrap().block_hash);

        // Store the metadata
        for meta in metadata {
            // TODO: Check the linkage of the returned chain
            self.chain_metadata.insert(meta.block_hash, meta);
        }

        // If the last block does not exist in our canonical history, fire the next request
        if self.db.get_block_by_hash(&last_hash)?.is_some() {
            // Hit our internal history. Start phase 2.
            self.p2_metadata = self.p1_metadata.clone();
        } else if DO_SPECULATIVE {
            self.request_missing_chain(None)?;
        }

        Ok(())
    }

    /// Returns the metadata of the chain from a given hash.
    ///
    /// This constructs a historical chain going backwards from a hash, by following the parent_hash.
    /// It collects N blocks and returns the metadata of that particular chain.
    /// This is mainly used in Phase 1 of the syncing algorithm, to construct a chain history.
    pub fn handle_metadata_request(
        &mut self,
        from: PeerId,
        request: RequestBlock,
    ) -> Result<ExternalMessage> {
        tracing::info!(
            "blockstore::MetadataRequest : received a metadata request from {}",
            from
        );

        // TODO: Check if we should service this request
        // Validators could respond to this request if there is nothing else to do.

        let batch_size: usize = self.max_batch_size.min(request.batch_size); // mitigate DOS by limiting the number of blocks we return
        let mut metas = Vec::with_capacity(batch_size);
        let mut hash = request.from_hash;
        while metas.len() < batch_size {
            // grab the parent
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                break; // that's all we have!
            };
            hash = block.parent_hash();
            metas.push(self.block_to_metadata(block));
        }

        let message = ExternalMessage::MetaDataResponse(metas);
        tracing::trace!(
            ?message,
            "blockstore::MetadataFromHash : responding to block request"
        );
        Ok(message)
    }

    /// Request missing chain from a peer.
    ///
    /// This constructs a chain history by requesting blocks from a peer, going backwards from a given block.
    /// If phase 1 is in progress, it continues requesting blocks from the last known phase 1 block.
    /// Otherwise, it requests blocks from the given omega_block.
    pub fn request_missing_chain(&mut self, omega_block: Option<Block>) -> Result<()> {
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "blockstore::RequestMissingChain : in-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.done_with_peer(DownGrade::Timeout);
            } else {
                return Ok(());
            }
        } else {
            if self.injected > 0 {
                tracing::warn!(
                    "blockstore::RequestMissingChain : too many {} blocks in flight",
                    self.injected
                );
                return Ok(());
            }
        }

        if let Some(peer) = self.get_next_peer() {
            let message = if let Some(meta) = self.p1_metadata.as_ref() {
                ExternalMessage::MetaDataRequest(RequestBlock {
                    from_number: 0,
                    from_hash: meta.parent_hash,
                    batch_size: self.max_batch_size,
                })
            } else if let Some(omega_block) = omega_block {
                let num = omega_block.number();
                let hash = omega_block.hash();
                ExternalMessage::MetaDataRequest(RequestBlock {
                    from_number: num,
                    from_hash: hash,
                    batch_size: self.max_batch_size,
                })
            } else {
                todo!("blockstore::RequestMissingChain : no metadata to request missing blocks");
            };

            tracing::info!(
                ?message,
                "blockstore::RequestMissingChain : requesting missing chain from {}",
                peer.peer_id
            );
            self.message_sender
                .send_external_message(peer.peer_id, message)?;

            self.in_flight = Some(peer);
        } else {
            tracing::warn!(
                "blockstore::RequestMissingChain : insufficient peers to request missing blocks"
            );
        }
        Ok(())
    }

    /// Request blocks from a hash, backwards.
    ///
    /// It will collect N blocks by following the block.parent_hash() of each requested block.
    pub fn handle_request_from_hash(
        &mut self,
        from: PeerId,
        request: RequestBlock,
    ) -> Result<ExternalMessage> {
        tracing::debug!(
            "blockstore::RequestFromHash : received a block request from {}",
            from
        );

        // TODO: Check if we should service this request
        // Validators could respond to this request if there is nothing else to do.

        let batch_size = self.max_batch_size.min(request.batch_size); // mitigate DOS by limiting the number of blocks we return
        let mut proposals = Vec::with_capacity(batch_size);
        let mut hash = request.from_hash;
        while proposals.len() < batch_size {
            // grab the parent
            let Some(block) = self.db.get_block_by_hash(&hash)? else {
                // that's all we have!
                break;
            };
            hash = block.parent_hash();
            proposals.push(self.block_to_proposal(block));
        }

        let message = ExternalMessage::ResponseFromHash(ResponseBlock { proposals });
        tracing::trace!(
            ?message,
            "blockstore::RequestFromHash : responding to block request from height"
        );
        Ok(message)
    }

    /// Request for blocks from a height, forwards.
    pub fn handle_request_from_number(
        &mut self,
        from: PeerId,
        request: RequestBlock,
    ) -> Result<ExternalMessage> {
        // ...
        tracing::debug!(
            "blockstore::RequestFromNumber : received a block request from {}",
            from
        );

        // TODO: Check if we should service this request.
        // Validators shall not respond to this request.

        // TODO: Replace this with a single SQL query
        let batch_size = self.max_batch_size.min(request.batch_size); // mitigate DOS attacks by limiting the number of blocks we send
        let mut proposals = Vec::with_capacity(batch_size);
        for num in request.from_number.saturating_add(1)
            ..=request.from_number.saturating_add(batch_size as u64)
        {
            let Some(block) = self.db.get_canonical_block_by_number(num)? else {
                // that's all we have!
                break;
            };
            proposals.push(self.block_to_proposal(block));
        }

        let message = ExternalMessage::ResponseFromNumber(ResponseBlock { proposals });
        tracing::trace!(
            ?message,
            "blockstore::RequestFromNumber : responding to block request from height"
        );
        Ok(message)
    }

    /// Inject the proposals into the chain.
    ///
    /// Besides pumping the set of Proposals into the processing pipeline, it also records the
    /// last known Proposal in the pipeline. This is used for speculative fetches, and also for
    /// knowing where to continue fetching from.
    fn inject_proposals(&mut self, proposals: Vec<Proposal>) -> Result<()> {
        if proposals.is_empty() {
            return Ok(());
        }

        // Store the tip
        let (last_block, _) = proposals.last().unwrap().clone().into_parts();
        self.latest_block = Some(last_block);

        // Increment proposals injected
        self.injected = self.injected.saturating_add(proposals.len());
        let len = proposals.len();

        // Just pump the Proposals back to ourselves.
        for p in proposals {
            tracing::trace!(
                "Injecting proposal number: {} hash: {}",
                p.number(),
                p.hash(),
            );

            self.message_sender.send_external_message(
                self.peer_id,
                ExternalMessage::InjectedProposal(InjectedProposal {
                    from: self.peer_id,
                    block: p,
                }),
            )?;
        }

        tracing::info!(
            "blockstore::InjectProposals : injected {}/{} proposals",
            len,
            self.injected
        );
        // return last proposal
        Ok(())
    }

    /// Downgrade a peer based on the response received.
    fn done_with_peer(&mut self, downgrade: DownGrade) {
        if let Some(mut peer) = self.in_flight.take() {
            // Downgrade peer, if necessary
            peer.score = peer.score.saturating_add(downgrade as u32);
            // Ensure that the next peer is equal or better, to avoid a single source of truth.
            peer.score = peer.score.max(self.peers.peek().unwrap().score);
            self.peers.push(peer);
        }
    }

    pub fn handle_response_from_number(
        &mut self,
        from: PeerId,
        response: ResponseBlock,
    ) -> Result<()> {
        // Process whatever we have received.
        if response.proposals.is_empty() {
            // Empty response, downgrade peer
            tracing::warn!("blockstore::ResponseFromNumber : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else if response.proposals.len() < self.max_batch_size {
            // Partial response, downgrade peer
            tracing::warn!("blockstore::ResponseFromNumber : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
        } else {
            self.done_with_peer(DownGrade::None);
        }

        tracing::info!(
            "blockstore::ResponseFromNumber : received {} blocks from {}",
            response.proposals.len(),
            from
        );

        // TODO: Any additional checks we should do here?

        // Sort proposals by number
        let proposals = response
            .proposals
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        // Insert into the cache.
        // If current proposal matches another one in cache, from a different peer, inject the proposal.
        // Else, replace the cached Proposal with the new one.
        let mut corroborated_proposals = Vec::with_capacity(proposals.len());
        let mut props = proposals.into_iter();

        // Collect corroborated proposals
        for p in props.by_ref() {
            if let Some(proposal) = self.cache.remove(&p.number()) {
                // If the proposal already exists
                if proposal.hash() == p.hash() {
                    // is corroborated proposal
                    corroborated_proposals.push(proposal);
                } else {
                    // insert the different one and;
                    self.cache.insert(p.number(), p);
                    break; // replace the rest in the next loop
                }
            } else {
                self.cache.insert(p.number(), p);
            }
        }

        // Replace/insert the rest of the proposals in the cache
        for p in props {
            self.cache.insert(p.number(), p);
        }

        // Inject matched proposals
        self.inject_proposals(corroborated_proposals)?;

        // Fire speculative request
        if self.latest_block.is_some() && self.injected < self.max_blocks_in_flight {
            if let Some(peer) = self.get_next_peer() {
                // we're far from latest block
                let message = RequestBlock {
                    from_number: self.latest_block.as_ref().unwrap().number(),
                    from_hash: self.latest_block.as_ref().unwrap().hash(),
                    batch_size: self.max_batch_size,
                };
                tracing::info!(
                    "blockstore::RequestMissingBlocks : speculative fetch {} blocks at {} from {}",
                    message.batch_size,
                    message.from_number,
                    peer.peer_id,
                );
                self.message_sender.send_external_message(
                    peer.peer_id,
                    ExternalMessage::RequestFromNumber(message),
                )?;
                self.in_flight = Some(peer);
            }
        }

        Ok(())
    }

    pub fn handle_response_from_hash(
        &mut self,
        from: PeerId,
        response: ResponseBlock,
    ) -> Result<()> {
        // Check that we have enough to complete the process, otherwise ignore
        if response.proposals.is_empty() {
            // Empty response, downgrade peer, skip
            tracing::warn!("blockstore::ResponseFromHash : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else if response.proposals.len() < GAP_THRESHOLD {
            // Partial response, downgrade peer
            // Skip processing because we want to ensure that we have ALL the needed blocks to sync up.
            tracing::warn!("blockstore::ResponseFromHash : partial blocks {from}",);
            self.done_with_peer(DownGrade::Partial);
            return Ok(());
        } else {
            // only process full responses
            self.done_with_peer(DownGrade::None);
        }

        tracing::info!(
            "blockstore::ResponseFromHash : received {} blocks from {}",
            response.proposals.len(),
            from
        );

        // TODO: Any additional checks we should do here?
        // Sort proposals by number
        let proposals = response
            .proposals
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        // Inject the proposals
        self.inject_proposals(proposals)?;
        Ok(())
    }

    /// Add a peer to the list of peers.
    pub fn add_peer(&mut self, peer: PeerId) {
        // new peers should be tried last, which gives them time to sync first.
        let new_peer = PeerInfo {
            score: self.peers.iter().map(|p| p.score).max().unwrap_or_default(),
            peer_id: peer,
            last_used: Instant::now(),
        };
        self.peers.push(new_peer);
    }

    /// Remove a peer from the list of peers.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.retain(|p| p.peer_id != peer);
    }

    fn get_next_peer(&mut self) -> Option<PeerInfo> {
        // Minimum of 2 peers to avoid single source of truth.
        if self.peers.len() < 2 {
            return None;
        }

        let mut peer = self.peers.pop()?;
        peer.last_used = std::time::Instant::now(); // used to determine stale in-flight requests.
        Some(peer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerInfo {
    score: u32,
    peer_id: PeerId,
    last_used: Instant,
}

impl Ord for PeerInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .cmp(&self.score)
            .then_with(|| other.last_used.cmp(&self.last_used))
    }
}

impl PartialOrd for PeerInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
