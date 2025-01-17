use std::{
    cmp::Ordering,
    collections::{BinaryHeap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::BlockNumber;
use anyhow::Result;
use itertools::Itertools;
use libp2p::PeerId;
use rusqlite::{
    named_params,
    types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef},
    OptionalExtension,
};

use crate::{
    cfg::NodeConfig,
    crypto::Hash,
    db::Db,
    message::{
        Block, BlockRequest, BlockRequestV2, BlockResponse, ChainMetaData, ExternalMessage,
        InjectedProposal, Proposal,
    },
    node::MessageSender,
    time::SystemTime,
};

// Syncing Algorithm
//
// When a Proposal is received by Consensus, we check if the parent exists in our DB.
// If not, then it triggers a syncing algorithm.
//
// PHASE 1: Request missing chain metadata.
// The entire chain metadata is stored in-memory, and is used to construct a chain of metadata.
// Each metadata basically contains the block_hash, block_number, parent_hash, and view_number.
// 1. We start with the latest Proposal and request the chain of metadata from a peer.
// 2. We construct the chain of metadata, based on the response received.
// 3. If the last block does not exist in our history, we request for additional metadata.
// 4. If the last block exists, we have hit our history, we move to Phase 2.
//
// PHASE 2: Request missing blocks.
// Once the chain metadata is constructed, we fill in the missing blocks to replay the history.
// We do not make any judgements (other than sanity) on the block and leave that up to consensus.
// 1. We construct a set of hashes, from the in-memory chain metadata.
// 2. We request these blocks from the same Peer that sent the metadata.
// 3. We inject the received Proposals into the pipeline.
// 4. If there are still missing blocks, we ask for more.
// 5. If there are no more missing blocks, we move to Phase 3.
//
// PHASE 3: Zip it up.
// Phase 1&2 may run several times and bring up 99% of the chain, but it will never catch up.
// This closes the final gap.
// 1. We queue all recently received Proposals, while Phase 1 & 2 were in progress.
// 2. We check the head of the queue, if its parent exists in our history.
// 3. If it does not, our history is too far away, we run Phase 1 again.
// 4. If it does, we inject the entire queue into the pipeline.
// 5. We are fully synced.

#[derive(Debug)]
pub struct Sync {
    // database
    db: Arc<Db>,
    // message bus
    message_sender: MessageSender,
    // internal list of peers, maintained with add_peer/remove_peer.
    peers: BinaryHeap<PeerInfo>,
    // peer handling an in-flight request
    in_flight: Option<PeerInfo>,
    // in-flight request timeout, before retry
    request_timeout: Duration,
    // how many blocks to request at once
    max_batch_size: usize,
    max_batch_size_const: usize,
    // how many blocks to inject into the queue
    max_blocks_in_flight: usize,
    // count of proposals pending in the pipeline
    in_pipeline: usize,
    // our peer id
    peer_id: PeerId,
    // internal sync state
    state: SyncState,
    // fixed-size queue of the most recent proposals
    recent_proposals: VecDeque<Proposal>,
    // for statistics only
    inject_at: Option<(std::time::Instant, usize)>,
    // record starting number, for eth_syncing() RPC call.
    started_at_block_number: u64,
}

impl Sync {
    // Speed up syncing by speculatively fetching blocks in Phase 1 & 2.
    #[cfg(not(debug_assertions))]
    const DO_SPECULATIVE: bool = true;
    #[cfg(debug_assertions)]
    const DO_SPECULATIVE: bool = false;

    // Minimum of 2 peers to avoid single source of truth.
    const MIN_PEERS: usize = 2;

    pub fn new(
        config: &NodeConfig,
        db: Arc<Db>,
        message_sender: MessageSender,
        peers: Vec<PeerId>,
    ) -> Result<Self> {
        let peers = peers
            .into_iter()
            .map(|peer_id| PeerInfo {
                version: PeerVer::V1, // default to V1 peer, until otherwise proven.
                score: 0,
                peer_id,
                last_used: Instant::now(),
            })
            .collect();
        let peer_id = message_sender.our_peer_id;
        let max_batch_size = config.block_request_batch_size.clamp(30, 180); // up to 180 sec of blocks at a time.
        let max_blocks_in_flight = config.max_blocks_in_flight.clamp(max_batch_size, 1800); // up to 30-mins worth of blocks in-pipeline.

        // This DB could be left in-here as it is only used in this module
        // TODO: Make this in-memory by exploiting SQLite TEMP tables i.e. CREATE TEMP TABLE
        db.with_sqlite_tx(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS sync_data (
                block_hash BLOB NOT NULL UNIQUE,
                parent_hash BLOB NOT NULL,
                block_number INTEGER NOT NULL PRIMARY KEY,
                view_number INTEGER NOT NULL,
                peer BLOB DEFAULT NULL,
                version INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_sync_data ON sync_data(block_number) WHERE peer IS NOT NULL;",
            )?;
            Ok(())
        })?;

        // Restore metadata/segments
        let mut segments = 0;
        db.with_sqlite_tx(|c| {
            segments = c
                .prepare_cached("SELECT COUNT(block_number) FROM sync_data WHERE peer IS NOT NULL")?
                .query_row([], |row| row.get::<_, usize>(0))
                .optional()?
                .unwrap_or_default();
            Ok(())
        })?;
        let state = if segments == 0 {
            SyncState::Phase0
        } else {
            SyncState::Retry1
        };

        Ok(Self {
            db,
            message_sender,
            peers,
            peer_id,
            request_timeout: config.consensus.consensus_timeout,
            max_batch_size,
            max_batch_size_const: max_batch_size,
            max_blocks_in_flight,
            in_flight: None,
            in_pipeline: usize::MIN,
            state,
            recent_proposals: VecDeque::with_capacity(max_batch_size),
            inject_at: None,
            started_at_block_number: 0,
        })
    }

    /// Returns the number of stored segments
    fn count_segments(&self) -> Result<usize> {
        let mut segments = 0;
        self.db.with_sqlite_tx(|c| {
            segments = c
                .prepare_cached("SELECT COUNT(block_number) FROM sync_data WHERE peer IS NOT NULL")?
                .query_row([], |row| row.get(0))
                .optional()?
                .unwrap_or_default();
            Ok(())
        })?;
        Ok(segments)
    }

    /// Checks if the stored metadata exists
    fn contains_metadata(&self, hash: &Hash) -> Result<bool> {
        let mut result = false;
        self.db.with_sqlite_tx(|c| {
            result = c
                .prepare_cached("SELECT block_number FROM sync_data WHERE block_hash = ?1")?
                .query_row([hash], |row| row.get::<_, u64>(0))
                .optional()?
                .is_some();
            Ok(())
        })?;
        Ok(result)
    }

    /// Retrieves bulk metadata information from the given block_hash (inclusive)
    fn get_segment(&self, hash: Hash) -> Result<Vec<Hash>> {
        let mut hashes = Vec::with_capacity(self.max_batch_size);
        let mut block_hash = hash;
        self.db.with_sqlite_tx(|c| {
            while let Some(parent_hash) = c
                .prepare_cached("SELECT parent_hash FROM sync_data WHERE block_hash = ?1")?
                .query_row([block_hash], |row| row.get::<_, Hash>(0))
                .optional()?
            {
                hashes.push(block_hash);
                block_hash = parent_hash;
            }
            Ok(())
        })?;
        Ok(hashes)
    }

    /// Peeks into the top of the segment stack.
    fn last_segment(&self) -> Result<Option<(ChainMetaData, PeerInfo)>> {
        let mut result = None;
        self.db.with_sqlite_tx(|c| {
            result = c
                .prepare_cached("SELECT parent_hash, block_hash, block_number, view_number, peer, version FROM sync_data WHERE peer IS NOT NULL ORDER BY block_number ASC LIMIT 1")?
                .query_row([], |row| Ok((
                    ChainMetaData{
                    parent_hash: row.get(0)?,
                    block_hash: row.get(1)?,
                    block_number: row.get(2)?,
                    view_number: row.get(3)?,
                },
                PeerInfo {
                    last_used: Instant::now(),
                    score:u32::MAX,
                    version: row.get(5)?,
                    peer_id: PeerId::from_bytes(row.get::<_,Vec<u8>>(4)?.as_slice()).unwrap(),
                },
            )))
                .optional()?;
            Ok(())
        })?;
        Ok(result)
    }

    /// Pops a segment from the stack; and bulk removes all metadata associated with it.
    fn pop_segment(&self) -> Result<()> {
        self.db.with_sqlite_tx(|c| {
            if let Some(block_hash) = c.prepare_cached("SELECT block_hash FROM sync_data WHERE peer IS NOT NULL ORDER BY block_number ASC LIMIT 1")?
            .query_row([], |row| row.get::<_,Hash>(0)).optional()? {
                if let Some(parent_hash) = c.prepare_cached("SELECT parent_hash FROM sync_data WHERE block_hash = ?1")?
                .query_row([block_hash], |row| row.get(0)).optional()? {

                // update marker
                c.prepare_cached(
                    "UPDATE sync_data SET peer = NULL WHERE block_hash = ?1")?
                    .execute(
                    [block_hash]
                )?;

                // remove segment                
                let mut hashes = Vec::with_capacity(self.max_batch_size);
                let mut block_hash = parent_hash;
                while let Some(parent_hash) = c
                        .prepare_cached("SELECT parent_hash FROM sync_data WHERE block_hash = ?1")?
                        .query_row([block_hash], |row| row.get::<_, Hash>(0))
                        .optional()?
                    {
                        hashes.push(block_hash);
                        block_hash = parent_hash;
                    }

                for hash in hashes {
                    c.prepare_cached("DELETE FROM sync_data WHERE block_hash = ?1")?
                    .execute([hash])?;
                }
                }
            }
            Ok(())
        })
    }

    /// Pushes a particular segment into the stack.
    fn push_segment(&self, peer: PeerInfo, meta: ChainMetaData) -> Result<()> {
        self.db.with_sqlite_tx(|c| {
            c.prepare_cached(
                "INSERT OR REPLACE INTO sync_data (parent_hash, block_hash, block_number, view_number, peer, version) VALUES (:parent_hash, :block_hash, :block_number, :view_number, :peer, :version)")?
                .execute(
                named_params! {
                    ":parent_hash": meta.parent_hash,
                    ":block_hash": meta.block_hash,
                    ":block_number": meta.block_number,
                    ":view_number": meta.view_number,
                    ":peer": peer.peer_id.to_bytes(),
                    ":version": peer.version,
                },
            )?;
            Ok(())
        })
    }

    /// Bulk inserts a bunch of metadata.
    fn insert_metadata(&self, metas: Vec<ChainMetaData>) -> Result<()> {
        self.db.with_sqlite_tx(|c| {
            for meta in metas {
            c.prepare_cached(
                "INSERT OR REPLACE INTO sync_data (parent_hash, block_hash, block_number, view_number) VALUES (:parent_hash, :block_hash, :block_number, :view_number)")?
                .execute(
                named_params! {
                    ":parent_hash": meta.parent_hash,
                    ":block_hash": meta.block_hash,
                    ":block_number": meta.block_number,
                    ":view_number": meta.view_number,
                },
            )?;
        }
            Ok(())
        })
    }

    /// Empty the metadata table.
    fn empty_metadata(&self) -> Result<()> {
        self.db.with_sqlite_tx(|c| {
            c.execute("DELETE FROM sync_data", [])?;
            Ok(())
        })
    }

    /// Phase 0: Sync a block proposal.
    ///
    /// This is the main entry point for syncing a block proposal.
    /// We start by enqueuing all proposals, and then check if the parent block exists in history.
    /// If the parent block exists, we do nothing. Otherwise, we check the least recent one.
    /// If we find its parent in history, we inject the entire queue. Otherwise, we start syncing.
    ///
    /// We do not perform checks on the Proposal here. This is done in the consensus layer.
    pub fn sync_proposal(&mut self, proposal: Proposal) -> Result<()> {
        // just stuff the latest proposal into the fixed-size queue.
        while self.recent_proposals.len() >= self.max_batch_size {
            self.recent_proposals.pop_front();
        }
        self.recent_proposals.push_back(proposal);

        self.sync_internal()
    }

    pub fn sync_internal(&mut self) -> Result<()> {
        if self.recent_proposals.is_empty() {
            // Do nothing if there's no recent proposals.
            tracing::debug!("sync::Internal : missing recent proposals");
            return Ok(());
        }

        match self.state {
            // Check if we are out of sync
            SyncState::Phase0 if self.in_pipeline == 0 => {
                let parent_hash = self.recent_proposals.back().unwrap().header.qc.block_hash;
                if self.db.get_block_by_hash(&parent_hash)?.is_none() {
                    // No parent block, trigger sync
                    tracing::warn!("sync::SyncProposal : syncing from {parent_hash}",);
                    let block_hash = self.recent_proposals.back().unwrap().hash();
                    let block_number = self.recent_proposals.back().unwrap().number();
                    let view_number = self.recent_proposals.back().unwrap().view();
                    let meta = ChainMetaData {
                        block_hash,
                        parent_hash,
                        block_number,
                        view_number,
                    };
                    self.request_missing_metadata(Some(meta))?;

                    let highest_block = self
                        .db
                        .get_canonical_block_by_number(
                            self.db
                                .get_highest_canonical_block_number()?
                                .expect("no highest block"),
                        )?
                        .expect("missing highest block");
                    self.started_at_block_number = highest_block.number();
                }
            }
            // Continue phase 1, until we hit history/genesis.
            SyncState::Phase1(_) if self.in_pipeline < self.max_batch_size => {
                self.request_missing_metadata(None)?;
            }
            // Continue phase 2, until we have all segments.
            SyncState::Phase2(_) if self.in_pipeline < self.max_blocks_in_flight => {
                self.request_missing_blocks()?;
            }
            // Wait till 99% synced, zip it up!
            SyncState::Phase3 if self.in_pipeline == 0 => {
                let ancestor_hash = self.recent_proposals.front().unwrap().header.qc.block_hash;
                if self.db.get_block_by_hash(&ancestor_hash)?.is_some() {
                    tracing::info!(
                        "sync::SyncProposal : finishing {} blocks for segment #{} from {}",
                        self.recent_proposals.len(),
                        self.count_segments()?,
                        self.peer_id,
                    );
                    // inject the proposals
                    let proposals = self.recent_proposals.drain(..).collect_vec();
                    self.inject_proposals(proposals)?;
                }
                self.empty_metadata()?;
                self.state = SyncState::Phase0;
            }
            // Retry to fix sync issues e.g. peers that are now offline
            SyncState::Retry1 if self.in_pipeline == 0 => {
                self.retry_phase1()?;
                if self.started_at_block_number == 0 {
                    let highest_block = self
                        .db
                        .get_canonical_block_by_number(
                            self.db
                                .get_highest_canonical_block_number()?
                                .expect("no highest block"),
                        )?
                        .expect("missing highest block");
                    self.started_at_block_number = highest_block.number();
                }
            }
            _ => {
                tracing::debug!(
                    "sync::SyncProposal : syncing {} blocks in pipeline",
                    self.in_pipeline
                );
            }
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
            parent_hash: block.parent_hash(),
            block_hash: block.hash(),
            block_number: block.number(),
            view_number: block.view(),
        }
    }

    /// Phase 2: Retry Phase 1
    ///
    /// If something went wrong in Phase 2, Phase 1 may need to be retried for the recently used segment.
    /// Things that could go wrong e.g. the peer went offline, the peer pruned history, etc.
    ///
    /// Pop the most recently used segment from the segment marker, and retry phase 1.
    /// This will rebuild history from the previous marker, with another peer.
    /// If this function is called many times, it will eventually restart from Phase 0.
    fn retry_phase1(&mut self) -> Result<()> {
        if self.count_segments()? == 0 {
            tracing::error!("sync::RetryPhase1 : cannot retry phase 1 without chain segments!");
            self.state = SyncState::Phase0;
            return Ok(());
        }

        tracing::debug!(
            "sync::RetryPhase1 : retrying segment #{}",
            self.count_segments()?,
        );

        // remove the last segment from the chain metadata
        let (meta, _) = self.last_segment()?.unwrap();
        self.pop_segment()?;
        self.state = SyncState::Phase1(meta);

        Ok(())
    }

    /// Phase 2: Handle a multi-block response.
    ///
    /// This is Phase 2 in the syncing algorithm, where we receive a set of blocks and inject them into the pipeline.
    /// We also remove the blocks from the chain metadata, because they are now in the pipeline.
    pub fn handle_multiblock_response(
        &mut self,
        from: PeerId,
        response: Vec<Proposal>,
    ) -> Result<()> {
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.peer_id != from {
                tracing::warn!(
                    "sync::MultiBlockResponse : unexpected peer={} != {from}",
                    peer.peer_id
                );
                return Ok(());
            }
        } else {
            tracing::warn!("sync::MultiBlockResponse : spurious response {from}");
            return Ok(());
        }

        // Process only a full response
        if response.is_empty() {
            // Empty response, downgrade peer and retry phase 1.
            tracing::warn!("sync::MultiBlockResponse : empty blocks {from}",);
            self.done_with_peer(DownGrade::Empty);
            self.state = SyncState::Retry1;
            return Ok(());
        } else {
            self.done_with_peer(DownGrade::None);
        }

        tracing::info!(
            "sync::MultiBlockResponse : received {} blocks for segment #{} from {}",
            response.len(),
            self.count_segments()?,
            from
        );

        // If the checksum does not match, retry phase 1. Maybe the node has pruned the segment.
        let SyncState::Phase2(check_sum) = self.state else {
            anyhow::bail!("sync::MultiBlockResponse : invalid state");
        };

        let checksum = response
            .iter()
            .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, p| {
                sum.with(p.hash().as_bytes())
            })
            .finalize();

        if check_sum != checksum {
            tracing::error!(
                "sync::MultiBlockResponse : unexpected checksum={check_sum} != {checksum}"
            );
            self.state = SyncState::Retry1;
            return Ok(());
        }

        // Response seems sane.
        let proposals = response
            .into_iter()
            .sorted_by_key(|p| p.number())
            .collect_vec();

        self.pop_segment()?;
        self.inject_proposals(proposals)?;

        // Done with phase 2
        if self.count_segments()? == 0 {
            self.state = SyncState::Phase3;
        } else if Self::DO_SPECULATIVE {
            // Speculatively request more blocks
            self.request_missing_blocks()?;
        }

        Ok(())
    }

    /// Returns a list of Proposals
    ///
    /// Given a set of block hashes, retrieve the list of proposals from its history.
    /// Returns this list of proposals to the requestor.
    pub fn handle_multiblock_request(
        &mut self,
        from: PeerId,
        request: Vec<Hash>,
    ) -> Result<ExternalMessage> {
        tracing::debug!(
            "sync::MultiBlockRequest : received a {} multiblock request from {}",
            request.len(),
            from
        );

        // TODO: Any additional checks
        // Validators should not respond to this, unless they are free e.g. stuck in an exponential backoff.

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

    /// Phase 2: Request missing blocks from the chain.
    ///
    /// It constructs a set of hashes, which constitute the series of blocks that are missing.
    /// These hashes are then sent to a Peer for retrieval.
    /// This is phase 2 of the syncing algorithm.
    fn request_missing_blocks(&mut self) -> Result<()> {
        if !matches!(self.state, SyncState::Phase2(_)) {
            anyhow::bail!("sync::RequestMissingBlocks : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "sync::RequestMissingBlocks : in-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.dynamic_batch_sizing(peer.peer_id, DownGrade::Timeout)?;
                self.done_with_peer(DownGrade::Timeout);
            } else {
                return Ok(());
            }
        } else if self.in_pipeline > self.max_blocks_in_flight {
            tracing::warn!(
                "sync::RequestMissingBlocks : syncing {} blocks in pipeline",
                self.in_pipeline
            );
            return Ok(());
        }

        // will be re-inserted below
        if let Some(peer) = self.get_next_peer() {
            // reinsert peer, as we will use a faux peer below, to force the request to go to the original responder
            self.peers.push(peer);

            // If we have no chain_segments, we have nothing to do
            if let Some((meta, peer_info)) = self.last_segment()? {
                let request_hashes = self.get_segment(meta.parent_hash)?;

                // Checksum of the request hashes
                let checksum = request_hashes
                    .iter()
                    .fold(Hash::builder().with(Hash::ZERO.as_bytes()), |sum, h| {
                        sum.with(h.as_bytes())
                    })
                    .finalize();
                self.state = SyncState::Phase2(checksum);

                // Fire request, to the original peer that sent the segment metadata
                tracing::info!(
                    "sync::RequestMissingBlocks : requesting {} blocks of segment #{} from {}",
                    request_hashes.len(),
                    self.count_segments()?,
                    peer_info.peer_id,
                );
                let message = match peer_info.version {
                    PeerVer::V2 => {
                        self.in_flight = Some(PeerInfo {
                            version: PeerVer::V2,
                            peer_id: peer_info.peer_id,
                            last_used: std::time::Instant::now(),
                            score: u32::MAX, // used to indicate faux peer, will not be added to the group of peers
                        });
                        ExternalMessage::MultiBlockRequest(request_hashes)
                    }
                    PeerVer::V1 => {
                        self.in_flight = Some(PeerInfo {
                            version: PeerVer::V1,
                            peer_id: peer_info.peer_id,
                            last_used: std::time::Instant::now(),
                            score: u32::MAX, // used to indicate faux peer, will not be added to the group of peers
                        });
                        // do not add VIEW_DRIFT - the stored marker is accurate!
                        ExternalMessage::BlockRequest(BlockRequest {
                            to_view: meta.view_number.saturating_sub(1),
                            from_view: meta.view_number.saturating_sub(self.max_batch_size as u64),
                        })
                    }
                };
                self.message_sender
                    .send_external_message(peer_info.peer_id, message)?;
            }
        } else {
            tracing::warn!("sync::RequestMissingBlocks : insufficient peers to handle request");
        }
        Ok(())
    }

    /// Phase 1: Dynamic Batch Sizing
    ///
    /// Due to a hard-coded 10MB response limit in libp2p, we may be limited in how many blocks we can request
    /// for in a single request, between 1-100 blocks.
    /// TODO: Make this a pro-active setting instead.
    fn dynamic_batch_sizing(&mut self, from: PeerId, reason: DownGrade) -> Result<()> {
        let Some(peer) = self.in_flight.as_ref() else {
            todo!("invalid peer");
        };

        match (&self.state, &peer.version, reason) {
            // V1 response may be too large. Reduce request range.
            (SyncState::Phase1(_), PeerVer::V1, DownGrade::Timeout) => {
                self.max_batch_size = self
                    .max_batch_size
                    .saturating_sub(self.max_batch_size / 2)
                    .max(1);
            }
            (SyncState::Phase1(_), PeerVer::V1, DownGrade::Empty) => {
                self.max_batch_size = self
                    .max_batch_size
                    .saturating_sub(self.max_batch_size / 3)
                    .max(1);
            }
            // V1 responses are going well, increase the request range linearly
            (SyncState::Phase1(_), PeerVer::V1, DownGrade::None) if from == peer.peer_id => {
                self.max_batch_size = self
                    .max_batch_size
                    .saturating_add(self.max_batch_size_const / 10)
                    // For V1, ~100 empty blocks saturates the response payload
                    .min(100);
            }
            // V2 response may be too large, which can induce a timeout. Split into 10 block segments
            _ => {}
        }

        Ok(())
    }

    /// Phase 1 / 2: Handle a V1 block response
    ///
    /// If the response if from a V2 peer, it will upgrade that peer to V2.
    /// In phase 1, it will extract the metadata and feed it into handle_metadata_response.
    /// In phase 2, it will extract the blocks and feed it into handle_multiblock_response.
    pub fn handle_block_response(&mut self, from: PeerId, response: BlockResponse) -> Result<()> {
        // Upgrade to V2 peer.
        if response.availability.is_none()
            && response.proposals.is_empty()
            && response.from_view == u64::MAX
        {
            tracing::info!("sync::HandleBlockResponse : upgrading {from}",);
            self.in_flight.as_mut().unwrap().version = PeerVer::V2;
            self.done_with_peer(DownGrade::None);
            return Ok(());
        }

        tracing::trace!(
            "sync::HandleBlockResponse : received {} blocks from {from}",
            response.proposals.len()
        );

        // Convert the V1 response into a V2 response.
        match self.state {
            // Phase 1 - construct the metadata chain from the set of received proposals
            SyncState::Phase1(ChainMetaData {
                block_number,
                mut parent_hash,
                ..
            }) => {
                // We do not buffer the proposals, as it takes 250MB/day!
                // Instead, we will re-request the proposals again, in Phase 2.
                let metadata = response
                    .proposals
                    .into_iter()
                    // filter extras due to drift
                    .filter(|p| p.number() < block_number)
                    .sorted_by(|a, b| b.number().cmp(&a.number()))
                    // filter any forks
                    .filter(|p| {
                        if parent_hash != p.hash() {
                            return false;
                        }
                        parent_hash = p.header.qc.block_hash;
                        true
                    })
                    .map(|p| ChainMetaData {
                        block_hash: p.hash(),
                        parent_hash: p.header.qc.block_hash,
                        block_number: p.number(),
                        view_number: p.view(),
                    })
                    .collect_vec();

                self.handle_metadata_response(from, metadata)?;
            }

            // Phase 2 - extract the requested proposals only.
            SyncState::Phase2(_) => {
                let multi_blocks = response
                    .proposals
                    .into_iter()
                    // filter any blocks that are not in the chain e.g. forks
                    .filter(|p| self.contains_metadata(&p.hash()).unwrap_or_default())
                    .sorted_by(|a, b| b.number().cmp(&a.number()))
                    .collect_vec();

                self.handle_multiblock_response(from, multi_blocks)?;
            }
            _ => {
                tracing::error!(
                    "sync::HandleBlockResponse : from={from} response={:?}",
                    response
                );
            }
        }
        Ok(())
    }

    /// Phase 1: Handle a response to a metadata request.
    ///
    /// This is the first step in the syncing algorithm, where we receive a set of metadata and use it to
    /// construct a chain history. We check that the metadata does indeed constitute a segment of a chain.
    /// If it does, we record its segment marker and store the entire chain in-memory.
    pub fn handle_metadata_response(
        &mut self,
        from: PeerId,
        response: Vec<ChainMetaData>,
    ) -> Result<()> {
        // Check for expected response
        let segment_peer = if let Some(peer) = self.in_flight.as_ref() {
            if peer.peer_id != from {
                tracing::warn!(
                    "sync::MetadataResponse : unexpected peer={} != {from}",
                    peer.peer_id
                );
                return Ok(());
            }
            peer.clone()
        } else {
            // We ignore any responses that arrived late, since the original request has already 'timed-out'.
            tracing::warn!("sync::MetadataResponse : spurious response {from}");
            return Ok(());
        };

        // Process whatever we have received.
        if response.is_empty() {
            // Empty response, downgrade peer and retry with a new peer.
            tracing::warn!("sync::MetadataResponse : empty blocks {from}",);
            self.dynamic_batch_sizing(from, DownGrade::Empty)?;
            self.done_with_peer(DownGrade::Empty);
            return Ok(());
        } else {
            self.dynamic_batch_sizing(from, DownGrade::None)?;
            self.done_with_peer(DownGrade::None);
        }

        // Check the linkage of the returned chain
        let SyncState::Phase1(meta) = &self.state else {
            anyhow::bail!("sync::MetadataResponse : invalid state");
        };

        let mut block_hash = meta.parent_hash;
        let mut block_num = meta.block_number;
        for meta in response.iter() {
            // check that the block hash and number is as expected.
            if meta.block_hash != Hash::ZERO
                && block_hash == meta.block_hash
                && block_num == meta.block_number + 1
            {
                block_hash = meta.parent_hash;
                block_num = meta.block_number;
            } else {
                // TODO: possibly, discard and rebuild entire chain
                // if something does not match, do nothing and retry the request with the next peer.
                tracing::error!(
                    "sync::MetadataResponse : unexpected metadata hash={block_hash} != {}, num={block_num} != {}",
                    meta.block_hash,
                    meta.block_number,
                );
                return Ok(());
            }
            if meta.block_hash == response.last().unwrap().block_hash {
                break; // done, we do not check the last parent, because that's outside this segment
            }
        }

        // Chain segment is sane
        let segment = response;

        // Record landmark, including peer that has this set of blocks
        self.push_segment(segment_peer, meta.clone())?;

        // Record the oldest block in the chain's parent
        self.state = SyncState::Phase1(segment.last().cloned().unwrap());
        let last_block_hash = segment.last().as_ref().unwrap().block_hash;

        tracing::info!(
            "sync::MetadataResponse : received {} metadata segment #{} from {}",
            segment.len(),
            self.count_segments()?,
            from
        );

        // Record the constructed chain metadata
        self.insert_metadata(segment)?;

        // If the segment hits our history, start Phase 2.
        if self.db.get_block_by_hash(&last_block_hash)?.is_some() {
            self.state = SyncState::Phase2(Hash::ZERO);
        } else if Self::DO_SPECULATIVE {
            self.request_missing_metadata(None)?;
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
        request: BlockRequestV2,
    ) -> Result<ExternalMessage> {
        tracing::debug!(
            "sync::MetadataRequest : received a metadata request from {}",
            from
        );

        // Do not respond to stale requests
        if request.request_at.elapsed()? > self.request_timeout {
            tracing::warn!("sync::MetadataRequest : stale request");
            return Ok(ExternalMessage::Acknowledgement);
        }

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
            "sync::MetadataFromHash : responding to block request"
        );
        Ok(message)
    }

    /// Phase 1: Request chain metadata from a peer.
    ///
    /// This constructs a chain history by requesting blocks from a peer, going backwards from a given block.
    /// If Phase 1 is in progress, it continues requesting blocks from the last known Phase 1 block.
    /// Otherwise, it requests blocks from the given starting metadata.
    pub fn request_missing_metadata(&mut self, meta: Option<ChainMetaData>) -> Result<()> {
        if !matches!(self.state, SyncState::Phase1(_)) && !matches!(self.state, SyncState::Phase0) {
            anyhow::bail!("sync::RequestMissingMetadata : invalid state");
        }
        // Early exit if there's a request in-flight; and if it has not expired.
        if let Some(peer) = self.in_flight.as_ref() {
            if peer.last_used.elapsed() > self.request_timeout {
                tracing::warn!(
                    "sync::RequestMissingMetadata : in-flight request {} timed out, requesting from new peer",
                    peer.peer_id
                );
                self.dynamic_batch_sizing(peer.peer_id, DownGrade::Timeout)?;
                self.done_with_peer(DownGrade::Timeout);
            } else {
                return Ok(());
            }
        } else if self.in_pipeline > self.max_batch_size {
            // anything more than this and we cannot be sure whether the segment hits history
            tracing::warn!(
                "sync::RequestMissingMetadata :  syncing {} blocks in pipeline",
                self.in_pipeline
            );
            return Ok(());
        }

        if let Some(peer) = self.get_next_peer() {
            tracing::info!(
                "sync::RequestMissingMetadata : requesting {} metadata of segment #{} from {}",
                self.max_batch_size,
                self.count_segments()? + 1,
                peer.peer_id
            );
            let message = match self.state {
                SyncState::Phase1(ChainMetaData { parent_hash, .. })
                    if matches!(peer.version, PeerVer::V2) =>
                {
                    ExternalMessage::MetaDataRequest(BlockRequestV2 {
                        request_at: SystemTime::now(),
                        from_hash: parent_hash,
                        batch_size: self.max_batch_size,
                    })
                }
                SyncState::Phase1(ChainMetaData { view_number, .. })
                    if matches!(peer.version, PeerVer::V1) =>
                {
                    // For V1 BlockRequest, we request a little more than we need, due to drift
                    // Since the view number is an 'internal' clock, it is possible for the same block number
                    // to have different view numbers.
                    let drift = self.max_batch_size as u64 / 10;
                    ExternalMessage::BlockRequest(BlockRequest {
                        to_view: view_number.saturating_add(drift),
                        from_view: view_number.saturating_sub(self.max_batch_size as u64),
                    })
                }
                SyncState::Phase0 if meta.is_some() && matches!(peer.version, PeerVer::V2) => {
                    let meta = meta.unwrap();
                    let parent_hash = meta.parent_hash;
                    self.state = SyncState::Phase1(meta);
                    ExternalMessage::MetaDataRequest(BlockRequestV2 {
                        request_at: SystemTime::now(),
                        from_hash: parent_hash,
                        batch_size: self.max_batch_size,
                    })
                }
                SyncState::Phase0 if meta.is_some() && matches!(peer.version, PeerVer::V1) => {
                    let meta = meta.unwrap();
                    let view_number = meta.view_number;
                    self.state = SyncState::Phase1(meta);
                    let drift = self.max_batch_size as u64 / 10;
                    ExternalMessage::BlockRequest(BlockRequest {
                        to_view: view_number.saturating_add(drift),
                        from_view: view_number.saturating_sub(self.max_batch_size as u64),
                    })
                }
                _ => anyhow::bail!("sync::MissingMetadata : invalid state"),
            };
            self.message_sender
                .send_external_message(peer.peer_id, message)?;
            self.in_flight = Some(peer);
        } else {
            tracing::warn!("sync::RequestMissingMetadata : insufficient peers to handle request");
        }
        Ok(())
    }

    /// Phase 2 / 3: Inject the proposals into the chain.
    ///
    /// It adds the list of proposals into the pipeline for execution.
    /// It also outputs some syncing statistics.
    fn inject_proposals(&mut self, proposals: Vec<Proposal>) -> Result<()> {
        if proposals.is_empty() {
            return Ok(());
        }

        // Output some stats
        if let Some((when, injected)) = self.inject_at {
            let diff = injected - self.in_pipeline;
            let rate = diff as f32 / when.elapsed().as_secs_f32();
            tracing::debug!("sync::InjectProposals : synced {} block/s", rate);
        }

        // Increment proposals injected
        self.in_pipeline = self.in_pipeline.saturating_add(proposals.len());
        tracing::debug!(
            "sync::InjectProposals : injecting {}/{} proposals",
            proposals.len(),
            self.in_pipeline
        );

        // Just pump the Proposals back to ourselves.
        for p in proposals {
            tracing::trace!(
                "sync::InjectProposals : injecting number: {} hash: {}",
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

        self.inject_at = Some((std::time::Instant::now(), self.in_pipeline));
        // return last proposal
        Ok(())
    }

    /// Mark a received proposal
    ///
    /// Mark a proposal as received, and remove it from the chain.
    pub fn mark_received_proposal(&mut self, prop: &InjectedProposal) -> Result<()> {
        if prop.from != self.peer_id {
            tracing::error!(
                "sync::MarkReceivedProposal : foreign InjectedProposal from {}",
                prop.from
            );
        }
        // if let Some(p) = self.chain_metadata.remove(&prop.block.hash()) {
        //     tracing::warn!(
        //         "sync::MarkReceivedProposal : removing stale metadata {}",
        //         p.block_hash
        //     );
        // }
        self.in_pipeline = self.in_pipeline.saturating_sub(1);
        Ok(())
    }

    /// Downgrade a peer based on the response received.
    ///
    /// This algorithm favours good peers that respond quickly (i.e. no timeout).
    /// In most cases, it eventually degenerates into 2 sources - avoid a single source of truth.
    fn done_with_peer(&mut self, downgrade: DownGrade) {
        if let Some(mut peer) = self.in_flight.take() {
            tracing::trace!("sync::DoneWithPeer {} {:?}", peer.peer_id, downgrade);
            peer.score = peer.score.saturating_add(downgrade as u32);
            // Ensure that the next peer is equal or better
            peer.score = peer.score.max(self.peers.peek().unwrap().score);
            // Reinsert peers that are good
            if peer.score < u32::MAX {
                self.peers.push(peer);
            }
        }
    }

    /// Add bulk peers
    pub fn add_peers(&mut self, peers: Vec<PeerId>) {
        for peer in peers {
            self.add_peer(peer);
        }
    }

    /// Add a peer to the list of peers.
    pub fn add_peer(&mut self, peer: PeerId) {
        // if the new peer is not synced, it will get downgraded to the back of heap.
        // but by placing them at the back of the 'best' pack, we get to try them out soon.
        let new_peer = PeerInfo {
            version: PeerVer::V1, // default V2
            score: self.peers.iter().map(|p| p.score).min().unwrap_or_default(),
            peer_id: peer,
            last_used: Instant::now(),
        };
        tracing::trace!("sync::AddPeer {peer}");
        // ensure that it is unique - avoids single source of truth
        self.peers.retain(|p: &PeerInfo| p.peer_id != peer);
        self.peers.push(new_peer);
    }

    /// Remove a peer from the list of peers.
    pub fn remove_peer(&mut self, peer: PeerId) {
        tracing::trace!("sync::RemovePeer {peer}");
        self.peers.retain(|p: &PeerInfo| p.peer_id != peer);
    }

    /// Get the next best peer to use
    fn get_next_peer(&mut self) -> Option<PeerInfo> {
        if self.peers.len() >= Self::MIN_PEERS {
            let mut peer = self.peers.pop()?;
            peer.last_used = std::time::Instant::now(); // used to determine stale requests.
            tracing::trace!("sync::GetNextPeer {} ({})", peer.peer_id, peer.score);
            return Some(peer);
        }
        None
    }

    /// Returns (am_syncing, current_highest_block)
    pub fn am_syncing(&self) -> Result<bool> {
        Ok(self.in_pipeline != 0
            || self.count_segments()? != 0
            || !self.recent_proposals.is_empty())
    }

    // Returns (starting_block, current_block,  highest_block) if we're syncing,
    // None if we're not.
    pub fn get_sync_data(&self) -> Result<Option<(BlockNumber, BlockNumber, BlockNumber)>> {
        let flag = self.am_syncing()?;
        if !flag {
            Ok(None)
        } else {
            let highest_block = self
                .db
                .get_canonical_block_by_number(
                    self.db
                        .get_highest_canonical_block_number()?
                        .expect("no highest block"),
                )?
                .expect("missing highest block");

            let highest_saved_block_number = highest_block.number();
            let highest_block_number_seen = self.recent_proposals.back().unwrap().number();
            Ok(Some((
                self.started_at_block_number,
                highest_saved_block_number,
                highest_block_number_seen,
            )))
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PeerInfo {
    score: u32,
    peer_id: PeerId,
    last_used: Instant,
    version: PeerVer,
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

/// For downgrading a peer from being selected in get_next_peer().
/// Ordered by degree of offence i.e. None is good, Timeout is worst
#[derive(Debug)]
enum DownGrade {
    None,
    Empty,
    Timeout,
}

/// Sync state
#[derive(Debug)]
enum SyncState {
    Phase0,
    Phase1(ChainMetaData),
    Phase2(Hash),
    Phase3,
    Retry1,
}

/// Peer Version
#[derive(Debug, Clone, Eq, PartialEq)]
enum PeerVer {
    V1 = 1,
    V2 = 2,
}

impl FromSql for PeerVer {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        u32::column_result(value).map(|i| match i {
            1 => PeerVer::V1,
            2 => PeerVer::V2,
            _ => todo!("invalid version"),
        })
    }
}

impl ToSql for PeerVer {
    fn to_sql(&self) -> Result<ToSqlOutput, rusqlite::Error> {
        Ok((self.clone() as u32).into())
    }
}
