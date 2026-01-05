use std::{
    cell::LazyCell,
    collections::{BTreeMap, HashMap, VecDeque},
    error::Error,
    fmt::Display,
    ops::RangeInclusive,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy::primitives::{Address, U256};
use anyhow::{Context, Result, anyhow};
use bitvec::{bitarr, order::Msb0};
use dashmap::DashMap;
use eth_trie::{EthTrie, MemoryDB, Trie};
use itertools::Itertools;
use k256::pkcs8::der::DateTime;
use libp2p::PeerId;
use opentelemetry::KeyValue;
use parking_lot::{Mutex, RwLock, RwLockWriteGuard};
use revm::Inspector;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tracing::*;

use crate::{
    api::{admin::merge_history, types::eth::SyncingStruct},
    aux, blockhooks,
    cfg::{ConsensusConfig, ForkName, NodeConfig},
    constants::{
        EXPONENTIAL_BACKOFF_TIMEOUT_MULTIPLIER, LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_WINDOW,
        TIME_TO_ALLOW_PROPOSAL_BROADCAST,
    },
    crypto::{BlsSignature, Hash, NodePublicKey, SecretKey, verify_messages},
    db::{self, BlockFilter, Db},
    evm::ZQ2EvmContext,
    exec::TransactionApplyResult,
    inspector::{ScillaInspector, TouchedAddressInspector},
    message::{
        AggregateQc, BitArray, BitSlice, Block, BlockHeader, BlockRef, BlockStrategy,
        ExternalMessage, GossipSubTopic, InternalMessage, MAX_COMMITTEE_SIZE, NewView, Proposal,
        QuorumCertificate, Vote,
    },
    node::{MessageSender, NetworkMessage},
    pool::{
        PendingOrQueued, TransactionPool, TxAddResult, TxPoolContent, TxPoolContentFrom,
        TxPoolStatus,
    },
    state::{Code, State},
    static_hardfork_data::{
        XSGD_CODE, XSGD_MAINNET_ADDR, build_ignite_wallet_addr_scilla_code_map,
    },
    sync::{Sync, SyncPeers},
    time::SystemTime,
    transaction::{
        EvmGas, SignedTransaction, TransactionReceipt, ValidationOutcome, VerifiedTransaction,
    },
};

#[derive(Clone, Debug, Serialize)]
pub struct NewViewVote {
    signatures: Vec<BlsSignature>,
    pub cosigned: BitArray,
    cosigned_weight: u128,
    qcs: BTreeMap<usize, QuorumCertificate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Validator {
    pub public_key: NodePublicKey,
    pub peer_id: PeerId,
}

impl PartialEq for Validator {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
    }
}

impl Eq for Validator {}

impl PartialOrd for Validator {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Validator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.peer_id.cmp(&other.peer_id)
    }
}

#[derive(Debug)]
struct MissingBlockError(BlockRef);

impl Display for MissingBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing block: {:?}", self.0)
    }
}

impl Error for MissingBlockError {}

impl From<u64> for MissingBlockError {
    fn from(view: u64) -> Self {
        MissingBlockError(BlockRef::View(view))
    }
}

impl From<Hash> for MissingBlockError {
    fn from(hash: Hash) -> Self {
        MissingBlockError(BlockRef::Hash(hash))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockVotes {
    pub signatures: Vec<BlsSignature>,
    pub cosigned: BitArray,
    pub cosigned_weight: u128,
    pub supermajority_reached: bool,
}

impl Default for BlockVotes {
    fn default() -> BlockVotes {
        BlockVotes {
            signatures: Vec::new(),
            cosigned: bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE],
            cosigned_weight: 0,
            supermajority_reached: false,
        }
    }
}

type EarlyProposal = (
    Block,
    Vec<VerifiedTransaction>,
    EthTrie<MemoryDB>,
    EthTrie<MemoryDB>,
    u128, // Cumulative gas fee which will be sent to ZERO account
);

#[derive(Debug)]
struct ReceiptsCache {
    hash: Hash,
    receipts: HashMap<Hash, (TransactionReceipt, Vec<Address>)>,
}

impl Default for ReceiptsCache {
    fn default() -> Self {
        Self {
            hash: Hash::ZERO,
            receipts: Default::default(),
        }
    }
}

impl ReceiptsCache {
    fn insert(&mut self, hash: Hash, receipt: TransactionReceipt, touched_addresses: Vec<Address>) {
        self.receipts.insert(hash, (receipt, touched_addresses));
    }

    fn set_hash(&mut self, hash: Hash) {
        self.hash = hash;
    }

    fn remove(&mut self, hash: &Hash) -> Option<(TransactionReceipt, Vec<Address>)> {
        self.receipts.remove(hash)
    }

    fn clear(&mut self) {
        self.hash = Hash::ZERO;
        self.receipts.clear();
    }
}

/// The consensus algorithm is pipelined fast-hotstuff, as given in this paper: https://arxiv.org/pdf/2010.11454.pdf
///
/// The algorithm can be condensed down into the following explanation:
/// - Blocks must contain either a QuorumCertificate (QC), or an aggregated QuorumCertificate (aggQC).
/// - A QuorumCertificate is an aggregation of signatures of threshold validators against a block hash (the previous block)
/// - An aggQC is an aggregation of threshold QC.
/// - at each time step, a.k.a 'view' a leader is chosen (based on view number) from the validators (committee) to propose a block
/// - committee members vote (create a signature) on the block proposal
/// - after threshold signatures are aggregated, a QC is formed which points to the block proposal
///
/// Happy path:
/// - Start at genesis, there is only a block with a dummy QC which everyone sees (exceptional case).
/// - everyone advances view to 1
/// - validators vote on genesis
/// - a high QC (QC pointing to the highest known hash) is formed from the validators votes on genesis
/// - everyone advances view to 2
/// - next leader proposes a block
/// - validators vote on block 1 -> new high QC... and so on.
///
/// Unhappy path:
/// - In the unhappy path, there is the possibility of forks (for example if you executed the block proposal).
/// - In this case, the view will time out with no leader successfully proposing a block.
/// - From this point forward, block view =/= block number
/// - The view will increment on all or some nodes. The timeout for view increments doubles each time,
///   which guarantees all nodes eventually are on the same view
/// - Nodes send a NewView message, which is a signature over the view, and their highQC
/// - This is collected to form an aggQC
/// - This aggQC is used to propose a block
/// - The votes on that block form the next highQC
///
#[derive(Debug)]
pub struct Consensus {
    secret_key: SecretKey,
    pub config: NodeConfig,
    message_sender: MessageSender,
    reset_timeout: UnboundedSender<Duration>,
    pub sync: Sync,
    pub votes: DashMap<Hash, BlockVotes>,
    /// Votes for a block we don't have stored. They are retained in case we receive the block later.
    // TODO(#719): Consider how to limit the size of this.
    pub buffered_votes: DashMap<Hash, Vec<(PeerId, Vote)>>,
    pub new_views: DashMap<u64, NewViewVote>,
    network_message_cache: Option<NetworkMessage>,
    pub high_qc: QuorumCertificate,
    /// The account store.
    state: State,
    /// The persistence database
    pub db: Arc<Db>,
    receipts_cache: Mutex<ReceiptsCache>,
    /// Actions that act on newly created blocks
    pub transaction_pool: Arc<RwLock<TransactionPool>>,
    /// Pending proposal. Gets created as soon as we become aware that we are leader for this view.
    early_proposal: RwLock<Option<EarlyProposal>>,
    /// Flag indicating that block broadcasting should be postponed at least until block_time is reached
    create_next_block_on_timeout: AtomicBool,
    /// Timestamp of most recent view change
    view_updated_at: RwLock<SystemTime>,
    pub new_blocks: broadcast::Sender<BlockHeader>,
    pub new_receipts: broadcast::Sender<(TransactionReceipt, usize)>,
    pub new_transactions: broadcast::Sender<VerifiedTransaction>,
    pub new_transaction_hashes: broadcast::Sender<Hash>,
    /// Used for testing and test network recovery
    force_view: Option<(u64, DateTime)>,
    /// Mark if this node is in the committee at it's current head block height
    in_committee: bool,
}

impl Consensus {
    // determined empirically
    const PROP_SIZE_THRESHOLD: usize = crate::constants::PROPOSAL_THRESHOLD;
    // view buffer size limit
    const VIEW_BUFFER_THRESHOLD: usize = 1000;

    pub fn new(
        secret_key: SecretKey,
        config: NodeConfig,
        message_sender: MessageSender,
        reset_timeout: UnboundedSender<Duration>,
        db: Arc<Db>,
        peers: Arc<SyncPeers>,
    ) -> Result<Self> {
        trace!(
            "Opening database in {:?} for shard {}",
            config.data_dir, config.eth_chain_id
        );

        // Start chain from checkpoint. Load data file and initialise data in tables
        let checkpoint_data = if let Some(checkpoint) = &config.load_checkpoint {
            trace!("Loading state from checkpoint: {:?}", checkpoint);
            let path = PathBuf::from(checkpoint.file.clone());
            db.load_trusted_checkpoint(path, &checkpoint.hash, config.eth_chain_id)?
        } else {
            None
        };

        let latest_block = db
            .get_finalized_view()?
            .and_then(|view| {
                db.get_block_hash_by_view(view)
                    .expect("no header found at view {view}")
            })
            .and_then(|hash| {
                db.get_block(hash.into())
                    .expect("no block found for hash {hash}")
            });

        let mut state = if let Some(latest_block) = &latest_block {
            trace!("Loading state from latest block");
            State::new_at_root(
                db.state_trie()?,
                latest_block.state_root_hash().into(),
                config.clone(),
                db.clone(),
            )
        } else {
            trace!("Constructing new state from genesis");
            State::new_with_genesis(db.state_trie()?, config.clone(), db.clone())
        }?;

        let (ckpt_block, ckpt_transactions, ckpt_parent) =
            if let Some((block, transactions, parent, view_history)) = checkpoint_data {
                info!(
                    history = display(&view_history),
                    "~~~~~~~~~~> found in checkpoint"
                );
                *state.view_history.write() = view_history;
                (Some(block), Some(transactions), Some(parent))
            } else {
                (None, None, None)
            };

        let (latest_block, latest_block_view) = match latest_block {
            Some(l) => (Some(l.clone()), l.view()),
            None => {
                let genesis = Block::genesis(state.root_hash()?);
                (Some(genesis.clone()), 0)
            }
        };

        let (start_view, high_qc) = {
            match db.get_high_qc()? {
                Some(qc) => {
                    let high_block = db
                        .get_block(qc.block_hash.into())?
                        .ok_or_else(|| anyhow!("missing block that high QC points to!"))?;
                    let finalized_view = db
                        .get_finalized_view()?
                        .ok_or_else(|| anyhow!("missing latest finalized view!"))?;
                    let finalized_block = db
                        .get_block(BlockFilter::View(finalized_view))?
                        .ok_or_else(|| anyhow!("missing finalized block!"))?;

                    // If latest view was written to disk then always start from there. Otherwise start from (highest out of high block and finalised block) + 1
                    let start_view = db
                        .get_view()?
                        .or_else(|| {
                            Some(std::cmp::max(high_block.view(), finalized_block.view()) + 1)
                        })
                        .unwrap();

                    trace!(
                        "recovery: high_block view {0}, finalized_number {1}, start_view {2}",
                        high_block.view(),
                        finalized_view,
                        start_view
                    );

                    if finalized_view > high_block.view() {
                        // We know of a finalized view higher than the view in finalized_number; start there.
                        state.set_to_root(finalized_block.header.state_root_hash.into());
                    } else {
                        // The high_block contains the latest finalized view. Start there.
                        state.set_to_root(high_block.header.state_root_hash.into());
                    }

                    info!(
                        "During recovery, starting consensus at view {}, finalised view {}",
                        start_view, finalized_view
                    );
                    (start_view, qc)
                }
                None => {
                    let start_view = 1;
                    let finalized_view = 0;
                    // We always mark view 1 as voted even though we haven't voted yet, because we can only send a
                    // `Vote` for the genesis block. We can never send `NewView(1)`.
                    db.set_view(start_view, true)?;
                    db.set_finalized_view(finalized_view)?;
                    (start_view, QuorumCertificate::genesis())
                }
            }
        };

        let sync = Sync::new(
            &config,
            db.clone(),
            &latest_block,
            message_sender.clone(),
            peers.clone(),
        )?;

        let state_sync = config.db.state_sync;
        let forks = config.consensus.get_forks()?;
        let enable_ots_indices = config.enable_ots_indices;

        let mut consensus = Consensus {
            secret_key,
            config,
            sync,
            message_sender,
            reset_timeout,
            votes: DashMap::new(),
            buffered_votes: DashMap::new(),
            new_views: DashMap::new(),
            network_message_cache: None,
            high_qc,
            state,
            db: db.clone(),
            receipts_cache: Default::default(),
            transaction_pool: Default::default(),
            early_proposal: Default::default(),
            create_next_block_on_timeout: AtomicBool::new(false),
            view_updated_at: RwLock::new(SystemTime::now()),
            new_blocks: broadcast::Sender::new(4),
            new_receipts: broadcast::Sender::new(128),
            new_transactions: broadcast::Sender::new(128),
            new_transaction_hashes: broadcast::Sender::new(128),
            force_view: None,
            in_committee: true,
        };

        // If we're at genesis, add the genesis block and return
        if latest_block_view == 0 {
            if let Some(genesis) = latest_block {
                // The genesis block might already be stored and we were interrupted before we got a
                // QC for it.
                if consensus.get_block(&genesis.hash())?.is_none() {
                    consensus.add_block(None, genesis.clone())?;
                }
                // Initialize state trie storage
                consensus.db.state_trie()?.init_state_trie(forks)?;
            }
            // treat genesis as finalized
            consensus.set_finalized_view(latest_block_view)?;
            return Ok(consensus);
        } else if enable_ots_indices {
            aux::check_and_build_ots_indices(db, latest_block_view)?;
        }

        // merge the missed view history imported from the database with the missed view
        // history loaded from the checkpoint, which is now stored in the consensus state
        let finalized_view = consensus.get_finalized_view()?;
        consensus.state.finalized_view = finalized_view;

        info!(
            view = start_view,
            finalized = finalized_view,
            history = display(&*consensus.state.view_history.read()),
            "~~~~~~~~~~> loaded from checkpoint in"
        );

        let max_missed_view_age = consensus.config.max_missed_view_age;

        let (first, last) = consensus.db.get_first_last_from_view_history()?;

        // import missed views and min_view from the db
        let imported_missed_views: Vec<(u64, NodePublicKey)> = consensus
            .db
            .read_recent_view_history(
                finalized_view.saturating_sub(max_missed_view_age + LAG_BEHIND_CURRENT_VIEW + 1),
            )?
            .iter()
            .map(|(view, bytes)| (*view, NodePublicKey::from_bytes(bytes).unwrap()))
            .collect();
        let imported_min_view = consensus.db.get_min_view_of_view_history()?;
        info!(
            min = imported_min_view,
            missed = imported_missed_views.len(),
            first,
            last,
            "~~~~~~~~~~> found in db"
        );

        // TODO(jailing): the first few missed views after the switchover are missing
        // in the genesis checkpoint, but it does not have any impact as it is long
        // before the jailing hardfork is actived

        // if the node was started without or with a checkpoint older than its finalized view
        if consensus.config.load_checkpoint.is_none()
            || finalized_view
                > ckpt_block
                    .as_ref()
                    .expect("Checkpoint block missing")
                    .view()
        {
            // if state_sync but no checkpoint is specified in the config then
            // the already started state syncing will be resumed, otherwise
            // it will be (re)started from the checkpoint specified
            if state_sync && let Some(ckpt_block) = ckpt_block.as_ref() {
                let new_history = consensus.state.view_history.read().new_at(
                    finalized_view,
                    finalized_view,
                    max_missed_view_age,
                );
                consensus.state.ckpt_view_history = Some(Arc::new(RwLock::new(new_history)));
                consensus.state.ckpt_finalized_view = Some(ckpt_block.view());
                // also persist the checkpoint's view history in the db otherwise
                // we won't be able to resume state syncing if the node is restarted
                let ckpt_view_history_guard =
                    consensus.state.ckpt_view_history.as_ref().unwrap().read();
                consensus
                    .db
                    .set_min_view_of_ckpt_view_history(ckpt_view_history_guard.min_view)?;
                for (view, leader) in ckpt_view_history_guard.missed_views.iter() {
                    consensus
                        .db
                        .extend_ckpt_view_history(*view, leader.as_bytes())?;
                }
            }
            {
                // store the imported missed views in the consensus state
                let mut history_guard = consensus.state.view_history.write();
                history_guard.missed_views.clear();
                history_guard
                    .missed_views
                    .extend(imported_missed_views.iter());
                // update the imported min_view in the consensus state
                history_guard.min_view = imported_min_view;
            }
            info!(
                view = start_view,
                finalized = finalized_view,
                history = display(&*consensus.state.view_history.read()),
                "~~~~~~~~~~> imported from db in"
            );
        } else {
            // store the missed views loaded from the checkpoint in the db
            {
                let history_guard = consensus.state.view_history.read();
                for (view, leader) in history_guard.missed_views.iter() {
                    // that were not found in the db
                    if *view < imported_min_view {
                        consensus.db.extend_view_history(*view, leader.as_bytes())?;
                    } else {
                        break;
                    }
                }
            }
            let earliest = consensus
                .config
                .consensus
                .get_forks()?
                .find_height_fork_first_activated(ForkName::ExecutableBlocks)
                .unwrap_or_default();
            info!(earliest, "~~~~~~~~~~>");
            {
                let mut history_guard = consensus.state.view_history.write();
                history_guard.min_view = history_guard.min_view.max(
                    earliest.saturating_sub(max_missed_view_age + LAG_BEHIND_CURRENT_VIEW + 1),
                );
                // update the min_view loaded from the checkpoint in the db
                consensus
                    .db
                    .set_min_view_of_view_history(history_guard.min_view)?;
            }
        }

        // If we started from a checkpoint
        if let (Some(block), Some(transactions), Some(parent)) =
            (ckpt_block, ckpt_transactions, ckpt_parent)
        {
            // if the checkpoint block does not exist, execute the block
            if consensus
                .db
                .get_transactionless_block(BlockFilter::Hash(block.hash()))?
                .is_none()
            {
                // if block is missing, execute the block
                consensus.state.set_to_root(parent.state_root_hash().into());
                consensus.execute_block(
                    None,
                    &block,
                    transactions,
                    &consensus
                        .state
                        .at_root(parent.state_root_hash().into())
                        .get_stakers(block.header)?,
                    true,
                )?;
            }
            // set starting point for state-sync/state-migration
            if state_sync {
                consensus.db.state_trie()?.set_migrate_at(block.number())?;
            }
        }

        // Initialize state trie storage
        consensus.db.state_trie()?.init_state_trie(forks)?;

        // If timestamp of when current high_qc was written exists then use it to estimate the minimum number of blocks the network has moved on since shut down
        // This is useful in scenarios in which consensus has failed since this node went down
        if let Some(latest_high_qc_timestamp) = consensus.db.get_high_qc_updated_at()? {
            let view_diff = Consensus::minimum_views_in_time_difference(
                latest_high_qc_timestamp.elapsed()?,
                consensus.config.consensus.consensus_timeout,
            );
            let min_view_since_high_qc_updated = high_qc.view + 1 + view_diff;
            if min_view_since_high_qc_updated > start_view {
                info!(
                    "Based on elapsed clock time of {} seconds since lastest high_qc update, we are atleast {} views above our current high_qc view. This is larger than our stored view so jump to new start_view {}",
                    latest_high_qc_timestamp.elapsed()?.as_secs(),
                    view_diff,
                    min_view_since_high_qc_updated
                );
                consensus
                    .db
                    .set_view(min_view_since_high_qc_updated, false)?;
            }
        }

        // Set self.network_message_cache incase the network is stuck
        if consensus.db.get_voted_in_view()? {
            let block = consensus.head_block();
            if let Some(leader) = consensus.leader_at_block(&block, consensus.get_view()?) {
                consensus.build_vote(leader.peer_id, consensus.vote_from_block(&block));
            }
        } else {
            consensus.build_new_view()?;
        }

        Ok(consensus)
    }

    fn build_new_view(&mut self) -> Result<NetworkMessage> {
        let view = self.get_view()?;
        let block = self.get_block(&self.high_qc.block_hash)?.ok_or_else(|| {
            anyhow!("missing block corresponding to our high qc - this should never happen")
        })?;
        let leader = self.leader_at_block(&block, view);
        let new_view_message = (
            leader.map(|leader: Validator| leader.peer_id),
            ExternalMessage::NewView(Box::new(NewView::new(
                self.secret_key,
                self.high_qc,
                view,
                self.secret_key.node_public_key(),
            ))),
        );

        self.network_message_cache = Some(new_view_message.clone());
        Ok(new_view_message)
    }

    fn build_vote(&mut self, peer_id: PeerId, vote: Vote) -> NetworkMessage {
        let network_msg = (Some(peer_id), ExternalMessage::Vote(Box::new(vote)));
        self.network_message_cache = Some(network_msg.clone());
        network_msg
    }

    pub fn public_key(&self) -> NodePublicKey {
        self.secret_key.node_public_key()
    }

    pub fn head_block(&self) -> Block {
        let highest_block_number = self
            .db
            .get_highest_canonical_block_number()
            .unwrap()
            .unwrap();
        self.db
            .get_block(BlockFilter::Height(highest_block_number))
            .unwrap()
            .unwrap()
    }

    pub fn get_highest_canonical_block_number(&self) -> u64 {
        self.db
            .get_highest_canonical_block_number()
            .unwrap()
            .unwrap()
    }

    pub fn get_lowest_block_view_number(&self) -> u64 {
        self.db.get_lowest_block_view_number().unwrap().unwrap()
    }

    /// Function is called when the node has no other work to do. Check if:
    ///     - Block should be proposed if we are leader
    ///     - View should be timed out because no proposal received in time
    ///     - Current view's NewView or Vote should be re-published
    pub fn timeout(&mut self) -> Result<Option<NetworkMessage>> {
        let view = self.get_view()?;
        // We never want to timeout while on view 1
        if view == 1 {
            let block = self
                .get_block_by_view(0)
                .unwrap()
                .ok_or_else(|| anyhow!("missing block"))?;
            // Get the list of stakers for the next block.
            let next_block_header = BlockHeader {
                number: block.number() + 1,
                ..block.header
            };
            let stakers = self.state.get_stakers(next_block_header)?;
            // If we're in the genesis committee, vote again.
            if stakers.iter().any(|v| *v == self.public_key()) {
                info!(
                    "timeout in view: {:?}, we will vote for block rather than incrementing view, block hash: {}",
                    view,
                    block.hash()
                );
                let leader = self.leader_at_block(&block, view).unwrap();
                let vote = self.vote_from_block(&block);
                let network_msg = self.build_vote(leader.peer_id, vote);
                return Ok(Some(network_msg));
            } else {
                info!(
                    "We are on view: {:?} but we are not a validator, so we are waiting.",
                    view
                );
            }

            return Ok(None);
        }

        let (
            milliseconds_since_last_view_change,
            milliseconds_remaining_of_block_time,
            exponential_backoff_timeout,
        ) = self.get_consensus_timeout_params()?;
        trace!(
            milliseconds_since_last_view_change,
            exponential_backoff_timeout,
            milliseconds_remaining_of_block_time,
            "timeout reached create_next_block_on_timeout: {:?}",
            self.create_next_block_on_timeout
        );

        if self.create_next_block_on_timeout.load(Ordering::SeqCst) {
            // Check if enough time elapsed to propose block
            if milliseconds_remaining_of_block_time == 0 {
                match self.propose_new_block(None) {
                    Ok(Some(network_message)) => {
                        self.create_next_block_on_timeout
                            .store(false, Ordering::SeqCst);
                        return Ok(Some(network_message));
                    }
                    Ok(None) => {
                        error!("Failed to finalise block proposal.");
                        self.create_next_block_on_timeout
                            .store(false, Ordering::SeqCst);
                        self.early_proposal_clear()?;
                    }
                    Err(e) => error!("Failed to finalise proposal: {e}"),
                };
            } else {
                self.reset_timeout
                    .send(Duration::from_millis(milliseconds_remaining_of_block_time))?;
                return Ok(None);
            }
        }

        // If we are not leader then consider whether we want to timeout - the timeout duration doubles every time, so it
        // Should eventually have all nodes on the same view
        if milliseconds_since_last_view_change < exponential_backoff_timeout {
            trace!(
                "Not proceeding with view change. Current view: {} - time since last: {}, timeout requires: {}",
                view, milliseconds_since_last_view_change, exponential_backoff_timeout
            );

            // Resend NewView message for this view if timeout period is a multiple of consensus_timeout
            if (milliseconds_since_last_view_change
                > self.config.consensus.consensus_timeout.as_millis() as u64)
                && !self.config.consensus.new_view_broadcast_interval.is_zero()
                && (Duration::from_millis(milliseconds_since_last_view_change)
                    .as_secs()
                    .is_multiple_of(self.config.consensus.new_view_broadcast_interval.as_secs()))
            {
                match self.network_message_cache.clone() {
                    Some((_, ExternalMessage::NewView(new_view))) => {
                        // If new_view message is not for this view then it must be outdated
                        if new_view.view == self.get_view()? {
                            // When re-sending new view messages we broadcast them, rather than only sending them to the
                            // view leader. This speeds up network recovery when many nodes have different high QCs.
                            self.new_view(self.peer_id(), *new_view.clone())?;
                            return Ok(Some((None, ExternalMessage::NewView(new_view))));
                        }
                    }
                    Some((peer, ExternalMessage::Vote(vote))) => {
                        if vote.view + 1 == self.get_view()? {
                            return Ok(Some((peer, ExternalMessage::Vote(vote))));
                        }
                    }
                    _ => {}
                }
            }

            return Ok(None);
        }

        trace!(
            "Considering view change: view: {} time since: {} timeout: {} last known view: {}, last height: {}, last hash: {}",
            view,
            milliseconds_since_last_view_change,
            exponential_backoff_timeout,
            self.high_qc.view,
            self.head_block().number(),
            self.head_block().hash()
        );

        let block = self.get_block(&self.high_qc.block_hash)?.ok_or_else(|| {
            anyhow!("missing block corresponding to our high qc - this should never happen")
        })?;

        // Get the list of stakers for the next block.
        let next_block_header = BlockHeader {
            number: block.number() + 1,
            ..block.header
        };
        let stakers = self
            .state
            .at_root(block.state_root_hash().into())
            .get_stakers(next_block_header)?;
        if !stakers.iter().any(|v| *v == self.public_key()) {
            debug!(
                "can't vote for new view, we aren't in the committee of length {:?}",
                stakers.len()
            );
            return Ok(None);
        }

        let next_view = view + 1;
        let next_exponential_backoff_timeout = self.exponential_backoff_timeout(next_view);
        info!(
            "***** TIMEOUT: View is now {} -> {}. Next view change in {}ms",
            view, next_view, next_exponential_backoff_timeout
        );

        self.set_view(next_view, false)?;
        let new_view = self.build_new_view()?;
        Ok(Some(new_view))
    }

    /// All values returned in milliseconds
    pub fn get_consensus_timeout_params(&self) -> Result<(u64, u64, u64)> {
        let view = self.get_view()?;
        let milliseconds_since_last_view_change = SystemTime::now()
            .duration_since(*self.view_updated_at.read())
            .unwrap_or_default();
        let mut milliseconds_remaining_of_block_time = self
            .config
            .consensus
            .block_time
            .saturating_sub(milliseconds_since_last_view_change);

        // In order to maintain close to 1 second block times we broadcast 1-TIME_TO_ALLOW_PROPOSAL_BROADCAST seconds after the previous block to allow for network messages and block processing
        if self.config.consensus.block_time > TIME_TO_ALLOW_PROPOSAL_BROADCAST {
            milliseconds_remaining_of_block_time = milliseconds_remaining_of_block_time
                .saturating_sub(TIME_TO_ALLOW_PROPOSAL_BROADCAST);
        }

        let mut exponential_backoff_timeout = self.exponential_backoff_timeout(view);

        // Override exponential_backoff_timeout in forced set view scenario
        match self.force_view {
            Some((forced_view, timeout_instant)) if view == forced_view => {
                exponential_backoff_timeout = SystemTime::from(timeout_instant)
                    .duration_since(SystemTime::now())?
                    .saturating_sub(milliseconds_since_last_view_change)
                    .as_millis() as u64;
            }
            _ => {}
        }

        Ok((
            milliseconds_since_last_view_change.as_millis() as u64,
            milliseconds_remaining_of_block_time.as_millis() as u64,
            exponential_backoff_timeout,
        ))
    }

    pub fn peer_id(&self) -> PeerId {
        self.secret_key.to_libp2p_keypair().public().to_peer_id()
    }

    /// Validate and process a fully formed proposal
    pub fn proposal(
        &mut self,
        from: PeerId,
        proposal: Proposal,
        during_sync: bool,
    ) -> Result<Option<NetworkMessage>> {
        self.cleanup_votes()?;

        let (block, transactions) = proposal.into_parts();
        let head_block = self.head_block();
        let mut view = self.get_view()?;

        info!(
            block_view = block.view(),
            block_number = block.number(),
            txns = transactions.len(),
            "handling block proposal {}",
            block.hash()
        );

        if self.db.contains_block(&block.hash())? {
            trace!("ignoring block proposal, block store contains this block already");
            return Ok(None);
        }

        if !during_sync && block.view() <= head_block.header.view {
            warn!(
                "Rejecting block - view not greater than our current head block! {} vs {}",
                block.view(),
                head_block.header.view
            );
            return Ok(None);
        }

        if block.gas_limit() > self.config.consensus.eth_block_gas_limit
            || block.gas_used() > block.gas_limit()
        {
            warn!(
                "Block gas used/limit check failed. Used: {}, Limit: {}, config limit: {}",
                block.gas_used(),
                block.gas_limit(),
                self.config.consensus.eth_block_gas_limit
            );
            return Ok(None);
        }

        if let Err(e) = self.check_block(&block, during_sync) {
            warn!(?e, "invalid block proposal received!");
            return Ok(None);
        }

        self.update_high_qc_and_view(block.agg.is_some(), block.header.qc)?;

        let proposal_view = block.view();
        let parent = self
            .get_block(&block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block parent"))?;

        trace!("checking if block view {} is safe", block.view());

        // If the proposed block is safe, vote for it and advance to the next round.
        if self.check_safe_block(&block)? {
            // If the proposed block is safe but outdated then add to block cache - we may need it later
            let outdated = block.view() < view;
            let process_immediately = !outdated || during_sync;
            if !process_immediately {
                trace!(
                    "proposal is outdated: {} < {} but may be useful in the future, buffering",
                    block.view(),
                    view
                );
                return Ok(None);
            }

            trace!(
                "block view {} number {} aka {} is safe",
                block.view(),
                block.number(),
                block.hash()
            );

            if head_block.hash() != parent.hash() || block.number() != head_block.header.number + 1
            {
                warn!(
                    "******* Fork detected! \nHead block: {:?} \nBlock prop: {:?}. We are node {}",
                    head_block,
                    block,
                    self.peer_id()
                );
                self.deal_with_fork(&block)?;
            }

            // Must make sure state root hash is set to the parent's state root hash before applying transactions
            if self.state.root_hash()? != parent.state_root_hash() {
                warn!(
                    "state root hash prior to block execution mismatch, expected: {:?}, actual: {:?}, head: {:?}",
                    parent.state_root_hash(),
                    self.state.root_hash()?,
                    head_block
                );
                self.state.set_to_root(parent.state_root_hash().into());
            }
            let stakers: Vec<_> = self.state.get_stakers(block.header)?;

            // It is possible to source Proposals from own storage during sync, which alters the source of the Proposal.
            // Only allow from == self, for fast-forwarding, in normal case but not during sync
            let from = (self.peer_id() != from || !during_sync).then_some(from);
            self.execute_block(from, &block, transactions, &stakers, during_sync)?;

            if view != proposal_view + 1 {
                view = proposal_view + 1;
                // We will send a vote in this view.
                self.set_view(view, true)?;
                debug!("*** setting view to proposal view... view is now {}", view);
            }

            if let Some((_, buffered_votes)) = self.buffered_votes.remove(&block.hash()) {
                // If we've buffered votes for this block, process them now.
                let count = buffered_votes.len();
                for (i, (from, vote)) in buffered_votes.into_iter().enumerate() {
                    trace!("applying buffered vote {} of {count}", i + 1);
                    if let Some(network_message) = self.vote(from, vote)? {
                        // If we reached the supermajority while processing this vote, send the next block proposal.
                        // Further votes are ignored (including our own).
                        // TODO(#720): We should prioritise our own vote.
                        trace!("supermajority reached, sending next proposal");
                        return Ok(Some(network_message));
                    }
                    // A bit hacky: processing of our buffered votes may have resulted in an early_proposal be created and awaiting empty block timeout for broadcast. In this case we must return now
                    let early_proposal = self.early_proposal.read();
                    if self.create_next_block_on_timeout.load(Ordering::SeqCst)
                        && early_proposal.is_some()
                        && early_proposal.as_ref().unwrap().0.view() == proposal_view + 1
                    {
                        trace!("supermajority reached, early proposal awaiting broadcast");
                        return Ok(None);
                    }
                }

                // If we reach this point, we had some buffered votes but they were not sufficient to reach a
                // supermajority.
            }

            // Get the list of stakers for the next block.
            let next_block_header = BlockHeader {
                number: block.number() + 1,
                ..block.header
            };
            let stakers = self.state.get_stakers(next_block_header)?;

            if !stakers.iter().any(|v| *v == self.public_key()) {
                self.in_committee(false)?;
                debug!(
                    "can't vote for block proposal, we aren't in the committee of length {:?}",
                    stakers.len()
                );
                return Ok(None);
            } else {
                self.in_committee(true)?;
                let vote = self.vote_from_block(&block);
                let next_leader = self.leader_at_block(&block, view);

                if self.create_next_block_on_timeout.load(Ordering::SeqCst) {
                    warn!("Create block on timeout set. Clearing");
                    self.create_next_block_on_timeout
                        .store(false, Ordering::SeqCst);
                }

                // Clear early_proposal in case it exists.
                self.early_proposal_clear()?;

                let Some(next_leader) = next_leader else {
                    warn!("Next leader is currently not reachable, has it joined committee yet?");
                    return Ok(None);
                };

                if !during_sync {
                    trace!(proposal_view, ?next_leader, "voting for block");
                    let network_message = self.build_vote(next_leader.peer_id, vote);
                    return Ok(Some(network_message));
                }
            }
        } else {
            trace!("block is not safe");
        }

        Ok(None)
    }

    /// For a given State apply a Proposal's rewards. Must be performed at the tail-end of the Proposal's processing.
    /// Note that the algorithm below is mentioned in cfg.rs - if you change the way
    /// rewards are calculated, please change the comments in the configuration structure there.
    fn apply_rewards_late_at(
        parent_block: &Block,
        at_state: &mut State,
        config: &ConsensusConfig,
        committee: &[NodePublicKey],
        proposer: NodePublicKey,
        block: &Block,
    ) -> Result<()> {
        let earned_reward = LazyCell::new(|| {
            let meter = opentelemetry::global::meter("zilliqa");
            meter
                .f64_counter("validator_earned_reward")
                .with_unit("ZIL")
                .build()
        });

        debug!("apply late rewards in view {}", block.view());
        let rewards_per_block: u128 = *config.rewards_per_hour / config.blocks_per_hour as u128;

        // Get the reward addresses from the parent state
        let parent_state = at_state.at_root(parent_block.state_root_hash().into());

        let proposer_address = parent_state.get_reward_address(proposer)?;

        let cosigner_stake: Vec<_> = committee
            .iter()
            .enumerate()
            .filter(|(i, _)| block.header.qc.cosigned[*i])
            .map(|(_, pub_key)| {
                let reward_address = parent_state.get_reward_address(*pub_key).unwrap();
                let stake = parent_state
                    .get_stake(*pub_key, block.header)
                    .unwrap()
                    .unwrap()
                    .get();
                (reward_address, stake)
            })
            .collect();

        let total_cosigner_stake = cosigner_stake.iter().fold(0, |sum, c| sum + c.1);
        if total_cosigner_stake == 0 {
            return Err(anyhow!("total stake is 0"));
        }

        // Track total awards given out. This may be different to rewards_per_block because we round down on division when we split the rewards
        let mut total_rewards_issued = 0;

        // Reward the Proposer
        if let Some(proposer_address) = proposer_address {
            let reward = rewards_per_block / 2;
            at_state.mutate_account(proposer_address, |a| {
                a.balance = a
                    .balance
                    .checked_add(reward)
                    .ok_or_else(|| anyhow!("Overflow occured in proposer account balance"))?;
                Ok(())
            })?;
            total_rewards_issued += reward;

            let attributes = [
                KeyValue::new("address", format!("{proposer_address:?}")),
                KeyValue::new("role", "proposer"),
            ];
            earned_reward.add((reward as f64) / 1e18, &attributes);
        }

        // Reward the committee
        for (reward_address, stake) in cosigner_stake {
            if let Some(cosigner) = reward_address {
                let reward = (U256::from(rewards_per_block / 2) * U256::from(stake)
                    / U256::from(total_cosigner_stake))
                .to::<u128>();
                at_state.mutate_account(cosigner, |a| {
                    a.balance = a
                        .balance
                        .checked_add(reward)
                        .ok_or(anyhow!("Overflow occured in cosigner account balance"))?;
                    Ok(())
                })?;
                total_rewards_issued += reward;

                let attributes = [
                    KeyValue::new("address", format!("{cosigner:?}")),
                    KeyValue::new("role", "cosigner"),
                ];
                earned_reward.add((reward as f64) / 1e18, &attributes);
            }
        }

        // ZIP-9: Fund rewards amount from zero account
        at_state.mutate_account(Address::ZERO, |a| {
            a.balance = a
                .balance
                .checked_sub(total_rewards_issued)
                .ok_or(anyhow!("No funds left in zero account"))?;
            Ok(())
        })?;

        Ok(())
    }

    /// For a given State apply the given transaction
    pub fn apply_transaction_at<I: Inspector<ZQ2EvmContext> + ScillaInspector>(
        state: &mut State,
        txn: VerifiedTransaction,
        current_block: BlockHeader,
        inspector: I,
        enable_inspector: bool,
    ) -> Result<Option<TransactionApplyResult>> {
        let hash = txn.hash;

        let result =
            state.apply_transaction(txn.clone(), current_block, inspector, enable_inspector);
        let result = match result {
            Ok(r) => r,
            Err(error) => {
                warn!(?hash, ?error, "transaction failed to execute");
                return Ok(None);
            }
        };

        if !result.success() {
            info!("Transaction was a failure...");
        }

        Ok(Some(result))
    }

    pub fn txpool_content(&self) -> TxPoolContent {
        let pool = self.transaction_pool.read();
        pool.preview_content()
    }

    pub fn txpool_content_from(&self, address: &Address) -> TxPoolContentFrom {
        let pool = self.transaction_pool.read();
        pool.preview_content_from(address)
    }

    pub fn txpool_status(&self) -> TxPoolStatus {
        let pool = self.transaction_pool.read();
        pool.preview_status()
    }

    pub fn get_pending_or_queued(
        &self,
        txn: &VerifiedTransaction,
    ) -> Result<Option<PendingOrQueued>> {
        let pool = self.transaction_pool.read();
        pool.get_pending_or_queued(txn)
    }

    /// This is total transactions for the account, including both executed and pending
    pub fn pending_transaction_count(&self, account_address: Address) -> u64 {
        let account_data = self.state.must_get_account(account_address);
        let current_nonce = account_data.nonce;
        let pool = self.transaction_pool.read();
        current_nonce + pool.account_pending_transaction_count(&account_address)
    }

    /// Clear up anything in memory that is no longer required. This is to avoid memory leaks.
    pub fn cleanup_votes(&self) -> Result<()> {
        // Wrt votes, we only care about votes on hashes for the current view or higher
        let finalized_view = self.get_finalized_view()?;
        self.votes.retain(|key, _| {
            if let Ok(Some(block)) = self.get_block(key) {
                // Remove votes for blocks that have been finalized. However, note that the block hashes which are keys
                // into `self.votes` are the parent hash of the (potential) block that is being voted on. Therefore, we
                // subtract one in this condition to ensure there is no chance of removing votes for blocks that still
                // have a chance of being mined. It is possible this is unnecessary, since `self.finalized_view` is
                // already at least 2 views behind the head of the chain, but keeping one extra vote in memory doesn't
                // cost much and does make us more confident that we won't dispose of valid votes.
                if block.view() < finalized_view.saturating_sub(1) {
                    trace!(block_view = %block.view(), block_hash = %key, "cleaning vote");
                    return false;
                }
            } else {
                warn!("Missing block for vote (this shouldn't happen), removing from memory");
                trace!(block_hash = %key, "cleaning vote");
                return false;
            }

            true
        });

        // Wrt new views, we only care about new views for the current view or higher
        let view = self.get_view()?;
        self.new_views.retain(|k, _| *k >= view);
        Ok(())
    }

    /// Process a Vote message
    pub fn vote(&self, peer_id: PeerId, vote: Vote) -> Result<Option<NetworkMessage>> {
        let block_hash = vote.block_hash;
        let block_view = vote.view;
        let current_view = self.get_view()?;
        info!(block_view, current_view, %block_hash, "handling vote from: {:?}", peer_id);

        // if the vote is too old; or too new
        if block_view + 1 < current_view {
            trace!("vote is too old");
            return Ok(None);
        } else if block_view > current_view + 500 {
            // when stuck in exponential backoff, +500 is effectively forever;
            // when active syncing at ~30 blk/s, means that we're > 3 views behind.
            // in either case, that vote is quite meaningless at this point and can be ignored.
            trace!("vote is too early");
            return Ok(None);
        }

        // Verify the signature in the vote matches the public key in the vote. This tells us that the vote was created
        // by the owner of `vote.public_key`, but we don't yet know that a vote from that node is valid. In other
        // words, a malicious node which is not part of the consensus committee may send us a vote and this check will
        // still pass. We later validate that the owner of `vote.public_key` is a valid voter.
        vote.verify()?;

        // Retrieve the actual block this vote is for.
        let Some(block) = self.get_block(&block_hash)? else {
            // We try to limit the size of the buffered votes to prevent memory exhaustion.
            // If the buffered votes exceed the threshold, we purge as many stale votes as possible.
            // While this is not guaranteed to reduce the size of the buffered votes, it is a best-effort attempt.
            if self.buffered_votes.len() > Self::VIEW_BUFFER_THRESHOLD {
                self.buffered_votes.retain(|_hash, votes| {
                    // purge stale votes
                    votes.first().map(|(_p, v)| v.view + 1).unwrap_or_default() >= current_view
                });
            }
            // If we don't have the block yet, we buffer the vote in case we recieve the block later. Note that we
            // don't know the leader of this view without the block, so we may be storing this unnecessarily, however
            // non-malicious nodes should only have sent us this vote if they thought we were the leader.
            let mut buf = self.buffered_votes.entry(block_hash).or_default();
            if buf.len() < MAX_COMMITTEE_SIZE {
                // we only ever need 2/3 of the committee, so it should not exceed this number.
                trace!("vote for unknown block, buffering");
                buf.push((peer_id, vote));
            } else {
                error!(%peer_id, view=%block_view, "vote for unknown block, dropping");
            }
            return Ok(None);
        };

        // if we are not the leader of the round in which the vote counts
        // The vote is in the happy path (?) - so the view is block view + 1
        if !self.are_we_leader_for_view(block_hash, block_view + 1) {
            trace!(
                vote_view = block_view + 1,
                ?block_hash,
                "skipping vote, not the leader"
            );
            return Ok(None);
        }

        let executed_block = BlockHeader {
            number: block.header.number + 1,
            ..Default::default()
        };

        let committee = self
            .state
            .at_root(block.state_root_hash().into())
            .get_stakers(executed_block)?;

        // verify the sender's signature on block_hash
        let Some((index, _)) = committee
            .iter()
            .enumerate()
            .find(|&(_, &v)| v == vote.public_key)
        else {
            warn!("Skipping vote outside of committee");
            return Ok(None);
        };

        let mut votes = self.votes.entry(block_hash).or_default();

        if votes.supermajority_reached {
            info!(
                "(vote) supermajority already reached in this view {}",
                current_view
            );
            return Ok(None);
        }

        // if the vote is new, store it
        if !votes.cosigned[index] {
            votes.signatures.push(vote.signature());
            votes.cosigned.set(index, true);
            // Update state to root pointed by voted block (in meantime it might have changed!)
            let state = self.state.at_root(block.state_root_hash().into());
            let Some(weight) = state.get_stake(vote.public_key, executed_block)? else {
                return Err(anyhow!("vote from validator without stake"));
            };
            votes.cosigned_weight += weight.get();

            let total_weight = self.total_weight(&committee, executed_block);
            votes.supermajority_reached = votes.cosigned_weight * 3 > total_weight * 2;

            trace!(
                cosigned_weight = votes.cosigned_weight,
                supermajority_reached = votes.supermajority_reached,
                total_weight,
                current_view,
                vote_view = block_view + 1,
                "storing vote"
            );
            // if we are already in the round in which the vote counts and have reached supermajority
            if votes.supermajority_reached {
                // We propose new block immediately if it is the first view
                // Otherwise the block will be proposed on timeout
                if current_view == 1 {
                    return self.propose_new_block(Some(&votes));
                }

                self.early_proposal_assemble_at(None)?;

                // It is possible that we have collected votes for a forked block. Do not propose in that case.
                let early_proposal = self.early_proposal.read();
                if let Some((block, _, _, _, _)) = early_proposal.as_ref()
                    && block.parent_hash() == block_hash
                {
                    std::mem::drop(early_proposal);
                    return self.ready_for_block_proposal(Some(&votes));
                }
            }
        }

        // The first time this is called, it assembles the early proposal.
        // Subsequent calls should have no effect, within the same view.
        self.early_proposal_assemble_at(None)?;

        Ok(None)
    }

    /// Finalise self.early_proposal.
    /// This should only run after majority QC or aggQC are available.
    /// It applies the rewards and produces the final Proposal.
    fn early_proposal_finish_at(
        &self,
        mut proposal: Block,
        cumulative_gas_fee: u128,
        votes: Option<&BlockVotes>,
    ) -> Result<Option<Block>> {
        // Retrieve parent block data
        let parent_block = self
            .get_block(&proposal.parent_hash())?
            .context("missing parent block")?;
        let parent_block_hash = parent_block.hash();

        let mut state = self.state.at_root(proposal.state_root_hash().into());

        // Compute the majority QC. If aggQC exists then QC is already set to correct value.
        let (final_qc, committee) = match proposal.agg {
            Some(_) => {
                let committee: Vec<_> = self.committee_for_hash(proposal.header.qc.block_hash)?;
                (proposal.header.qc, committee)
            }
            None => {
                // Check for majority
                let votes = match votes {
                    Some(v) => v,
                    None => match self.votes.get(&parent_block_hash) {
                        Some(v) => &v.clone(),
                        None => {
                            warn!("tried to finalise a proposal without any votes");
                            return Ok(None);
                        }
                    },
                };
                if !votes.supermajority_reached {
                    warn!("tried to finalise a proposal without majority");
                    return Ok(None);
                };
                // Retrieve the previous leader and committee - for rewards
                let committee = self
                    .state
                    .at_root(parent_block.state_root_hash().into())
                    .get_stakers(proposal.header)?;
                (
                    self.qc_from_bits(
                        parent_block_hash,
                        &votes.signatures,
                        votes.cosigned,
                        parent_block.view(),
                    ),
                    committee,
                )
            }
        };
        proposal.header.qc = final_qc;

        self.apply_proposal_to_state(
            &mut state,
            &proposal,
            &parent_block,
            &committee,
            cumulative_gas_fee,
        )?;

        // Finalise the proposal with final QC and state.
        let proposal = Block::from_qc(
            self.secret_key,
            proposal.header.view,
            proposal.header.number,
            // majority QC
            final_qc,
            proposal.agg,
            // post-reward updated state
            state.root_hash()?,
            proposal.header.transactions_root_hash,
            proposal.header.receipts_root_hash,
            proposal.transactions,
            proposal.header.timestamp, // set block timestamp to **start** point of assembly.
            proposal.header.gas_used,
            proposal.header.gas_limit,
        );
        self.receipts_cache
            .lock()
            .set_hash(proposal.header.receipts_root_hash);

        // Return the final proposal
        Ok(Some(proposal))
    }

    /// Assemble self.early_proposal.
    /// This is performed before the majority QC is available.
    /// It does all the needed work but with a dummy QC.
    fn early_proposal_assemble_at(&self, agg: Option<AggregateQc>) -> Result<()> {
        let view = self.get_view()?;
        {
            if let Some(early_proposal) = self.early_proposal.read().as_ref()
                && early_proposal.0.view() == view
            {
                return Ok(());
            }
        }

        let (qc, parent) = match agg {
            // Create dummy QC for now if aggQC not provided
            None => {
                // Start with highest canonical block
                let block = self
                    .db
                    .get_transactionless_block(BlockFilter::MaxCanonicalByHeight)?
                    .expect("missing canonical block");
                (
                    QuorumCertificate::new_with_identity(block.hash(), block.view()),
                    block,
                )
            }
            Some(ref agg) => {
                let qc = self.get_highest_from_agg(agg)?;
                let parent = self
                    .get_block(&qc.block_hash)?
                    .ok_or_else(|| anyhow!("missing block"))?;
                (qc, parent)
            }
        };

        // This is a partial header of a block that will be proposed with some transactions executed below.
        // It is needed so that each transaction is executed within proper block context (the block it belongs to)
        let executed_block_header = BlockHeader {
            view,
            number: parent.header.number + 1,
            timestamp: SystemTime::max(SystemTime::now(), parent.timestamp()), // block timestamp at **start** of assembly, not end.
            gas_limit: self.config.consensus.eth_block_gas_limit,
            ..BlockHeader::default()
        };

        debug!(
            "assemble early proposal view {} block number {}",
            executed_block_header.view, executed_block_header.number
        );

        // Ensure sane state
        let state = self.state.clone();
        if state.root_hash()? != parent.state_root_hash() {
            warn!(
                "state root hash mismatch, expected: {:?}, actual: {:?}",
                parent.state_root_hash(),
                state.root_hash()?
            );
        }

        // Clear internal receipt cache.
        // Since this is a speed enhancement, we're ignoring scenarios where the receipts cache may hold receipts for more than one proposal.
        self.receipts_cache.lock().clear();

        // Internal states
        let mut receipts_trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
        let mut transactions_trie: EthTrie<MemoryDB> = EthTrie::new(Arc::new(MemoryDB::new(true)));
        let applied_txs = Vec::<VerifiedTransaction>::new();

        // Generate the early proposal
        // Some critical parts are dummy/missing:
        // a. Majority QC is missing
        // b. Rewards have not been applied
        // c. transactions have not been added
        let proposal = Block::from_qc(
            self.secret_key,
            executed_block_header.view,
            executed_block_header.number,
            qc,
            agg,
            parent.state_root_hash(), // late state before transactions or rewards are applied
            Hash(transactions_trie.root_hash()?.into()),
            Hash(receipts_trie.root_hash()?.into()),
            vec![],
            executed_block_header.timestamp,
            EvmGas(0),
            executed_block_header.gas_limit,
        );

        let mut early_proposal = self.early_proposal.write();
        *early_proposal = Some((proposal, applied_txs, transactions_trie, receipts_trie, 0));
        self.early_proposal_apply_transactions(self.transaction_pool.write(), early_proposal)?;
        Ok(())
    }

    /// Updates self.early_proposal data (proposal, applied_transactions, transactions_trie, receipts_trie) to include any transactions in the mempool
    fn early_proposal_apply_transactions(
        &self,
        mut pool: RwLockWriteGuard<TransactionPool>,
        mut early_proposal: RwLockWriteGuard<Option<EarlyProposal>>,
    ) -> Result<()> {
        if early_proposal.is_none() {
            error!("could not apply transactions to early_proposal because it does not exist");
            return Ok(());
        }

        let mut state = self.state.clone();

        let proposal = early_proposal.as_ref().unwrap().0.clone();

        // Use state root hash of current early proposal
        state.set_to_root(proposal.state_root_hash().into());
        // Internal states
        let mut threshold_size = Self::PROP_SIZE_THRESHOLD;
        let mut gas_left = proposal.header.gas_limit - proposal.header.gas_used;
        let mut tx_index_in_block = proposal.transactions.len();

        // update the pool with the current state
        pool.update_with_state(&state);

        // Assemble new block with whatever is in the mempool
        while let Some(tx) = pool.pop_best_if(|txn| {
            // First - check if we have time left to process txns and give enough time for block propagation
            let (_, milliseconds_remaining_of_block_time, _) =
                self.get_consensus_timeout_params().unwrap();

            if milliseconds_remaining_of_block_time == 0 {
                debug!(number=%proposal.header.number,
                    "block out of time"
                );
                return false;
            }

            if gas_left < txn.tx.gas_limit() {
                debug!(?gas_left, gas_limit = ?txn.tx.gas_limit(), number=%proposal.header.number, "block out of gas");
                return false;
            }

            if txn.encoded_size() > threshold_size {
                debug!(number=%proposal.header.number, "block out of size");
                return false;
            }

            true
        }) {
            let tx = tx.clone();

            // Apply specific txn
            let mut inspector = TouchedAddressInspector::default();
            let result = Self::apply_transaction_at(
                &mut state,
                tx.clone(),
                proposal.header,
                &mut inspector,
                self.config.enable_ots_indices,
            )?;
            // Update the pool with the new state
            pool.update_with_state(&state);

            // Skip transactions whose execution resulted in an error and drop them.
            let Some(result) = result else {
                warn!("Dropping failed transaction: {:?}", tx.hash);
                continue;
            };

            // Reduce balance size threshold
            threshold_size -= tx.encoded_size();

            // Reduce remaining gas in this block
            gas_left = gas_left
                .checked_sub(result.gas_used())
                .ok_or_else(|| anyhow!("gas_used > gas_limit"))?;

            let gas_fee = result.gas_used().0 as u128 * tx.tx.gas_price_per_evm_gas();

            // Grab and update early_proposal data in own scope to avoid multiple mutable references to self
            {
                let (proposal, applied_txs, transactions_trie, receipts_trie, cumulative_gas_fee) =
                    early_proposal.as_mut().unwrap();

                *cumulative_gas_fee += gas_fee;
                transactions_trie.insert(tx.hash.as_bytes(), tx.hash.as_bytes())?;

                let receipt = Self::create_txn_receipt(
                    result,
                    tx.hash,
                    tx_index_in_block,
                    self.config.consensus.eth_block_gas_limit - gas_left,
                );

                let receipt_hash = receipt.compute_hash();
                debug!(
                    "During assembly in view: {}, transaction with hash: {:?} produced receipt: {:?}, receipt hash: {:?}",
                    proposal.header.view, tx.hash, receipt, receipt_hash
                );
                receipts_trie.insert(receipt_hash.as_bytes(), receipt_hash.as_bytes())?;

                // Forwarding cache
                let addresses = inspector.touched.into_iter().collect_vec();
                self.receipts_cache
                    .lock()
                    .insert(tx.hash, receipt, addresses);

                tx_index_in_block += 1;
                applied_txs.push(tx);
            }
        }
        std::mem::drop(pool);

        let (_, applied_txs, _, _, _) = early_proposal.as_ref().unwrap();
        self.db.with_sqlite_tx(|sqlite_tx| {
            for tx in applied_txs {
                self.db
                    .insert_transaction_with_db_tx(sqlite_tx, &tx.hash, tx)?;
            }
            Ok(())
        })?;

        // Grab and update early_proposal data in own scope to avoid multiple mutable references to Self
        {
            let (proposal, applied_txs, transactions_trie, receipts_trie, _) =
                early_proposal.as_mut().unwrap();

            let applied_transaction_hashes = applied_txs.iter().map(|tx| tx.hash).collect_vec();
            trace!(
                "applied {} transactions to early block for view {}",
                tx_index_in_block - proposal.transactions.len(),
                proposal.header.view
            );

            // Update proposal with transactions added
            proposal.header.state_root_hash = state.root_hash()?;
            proposal.header.transactions_root_hash = Hash(transactions_trie.root_hash()?.into());
            proposal.header.receipts_root_hash = Hash(receipts_trie.root_hash()?.into());
            proposal.transactions = applied_transaction_hashes;
            proposal.header.gas_used = proposal.header.gas_limit - gas_left;
        }

        // as a future improvement, process the proposal before broadcasting it
        Ok(())
    }

    /// Clear early_proposal and add it's transactions back to pool.
    /// This function should be called only when something has gone wrong.
    fn early_proposal_clear(&self) -> Result<()> {
        if let Some((_, txns, _, _, _)) = self.early_proposal.write().take() {
            let mut pool = self.transaction_pool.write();
            pool.update_with_state(&self.state);
            for txn in txns.into_iter().rev() {
                let account = self.state.get_account(txn.signer)?;
                let _added = pool.insert_transaction_forced(txn, &account, false);
            }
            warn!("early_proposal cleared. This is a consequence of some incorrect behaviour.");
        }
        Ok(())
    }

    /// Called when node has become leader and is ready to publish a Proposal.
    /// Either propose now or set timeout to allow for txs to come in.
    fn ready_for_block_proposal(
        &self,
        votes: Option<&BlockVotes>,
    ) -> Result<Option<NetworkMessage>> {
        // Check if there's enough time to wait on a timeout and then propagate an empty block in the network before other participants trigger NewView
        let (milliseconds_since_last_view_change, milliseconds_remaining_of_block_time, _) =
            self.get_consensus_timeout_params()?;

        if milliseconds_remaining_of_block_time == 0 {
            return self.propose_new_block(votes);
        }

        // Reset the timeout and wake up again once it has been at least `block_time` since
        // the last view change. At this point we should be ready to produce a new block.
        self.create_next_block_on_timeout
            .store(true, Ordering::SeqCst);
        self.reset_timeout.send(
            self.config
                .consensus
                .block_time
                .saturating_sub(Duration::from_millis(milliseconds_since_last_view_change)),
        )?;
        trace!(
            "will propose new proposal on timeout for view {}",
            self.get_view()?
        );

        Ok(None)
    }

    /// Produces the Proposal block by taking and finalising early_proposal.
    /// It must return a final Proposal with correct QC, regardless of whether it is empty or not.
    fn propose_new_block(&self, votes: Option<&BlockVotes>) -> Result<Option<NetworkMessage>> {
        // We expect early_proposal to exist already but try create incase it doesn't
        self.early_proposal_assemble_at(None)?;
        let mut early_proposal = self.early_proposal.write();
        let (pending_block, applied_txs, _, _, cumulative_gas_fee) = early_proposal.take().unwrap(); // safe to unwrap due to check above
        std::mem::drop(early_proposal);

        // intershard transactions are not meant to be broadcast
        let (mut broadcasted_transactions, opaque_transactions): (Vec<_>, Vec<_>) = applied_txs
            .clone()
            .into_iter()
            .partition(|tx| !matches!(tx.tx, SignedTransaction::Intershard { .. }));
        // however, for the transactions that we are NOT broadcasting, we re-insert
        // them into the pool - this is because upon broadcasting the proposal, we will
        // have to re-execute it ourselves (in order to vote on it) and thus will
        // need those transactions again
        {
            let mut pool = self.transaction_pool.write();
            for tx in opaque_transactions {
                let account = self.state.get_account(tx.signer)?;
                pool.update_with_account(&tx.signer, &account);
                pool.insert_transaction(tx, &account, true);
            }
        }

        // finalise the proposal
        let Some(final_block) =
            self.early_proposal_finish_at(pending_block, cumulative_gas_fee, votes)?
        else {
            // Do not Propose.
            // Recover the proposed transactions into the pool.
            let mut pool = self.transaction_pool.write();
            while let Some(txn) = broadcasted_transactions.pop() {
                let account = self.state.get_account(txn.signer)?;
                pool.update_with_account(&txn.signer, &account);
                let added = pool.insert_transaction(txn, &account, false);
                assert!(added.was_added())
            }
            return Ok(None);
        };

        info!(proposal_hash = ?final_block.hash(), ?final_block.header.view, ?final_block.header.number, txns = final_block.transactions.len(), "######### proposing block");

        Ok(Some((
            None,
            ExternalMessage::Proposal(Proposal::from_parts(final_block, broadcasted_transactions)),
        )))
    }

    /// Insert transaction and add to transaction pool.
    pub fn handle_new_transactions(
        &self,
        verified_transactions: Vec<VerifiedTransaction>,
        from_broadcast: bool,
    ) -> Result<Vec<TxAddResult>> {
        let mut inserted = Vec::with_capacity(verified_transactions.len());
        for txn in verified_transactions {
            info!(?txn, "seen new txn");
            inserted.push(self.new_transaction(txn, from_broadcast)?);
        }
        Ok(inserted)
    }

    pub fn try_early_proposal_after_txn_batch(&self) -> Result<()> {
        if self.create_next_block_on_timeout.load(Ordering::SeqCst) {
            let early_proposal = self.early_proposal.write();
            if early_proposal.is_some() {
                let pool = self.transaction_pool.write();
                if pool.has_txn_ready() {
                    trace!(
                        "add transaction to early proposal {}",
                        early_proposal.as_ref().unwrap().0.header.view
                    );

                    self.early_proposal_apply_transactions(pool, early_proposal)?;
                }
            }
        }
        Ok(())
    }

    /// Provides a (cached) preview of the early proposal.
    pub fn get_pending_block(&self) -> Result<Option<Block>> {
        if let Some(early_proposal) = self.early_proposal.read().as_ref()
            && early_proposal.0.view() == self.get_view()?
        {
            return Ok(Some(early_proposal.0.clone()));
        }
        self.early_proposal_assemble_at(None)?;
        Ok(Some(self.early_proposal.read().as_ref().unwrap().0.clone()))
    }

    fn are_we_leader_for_view(&self, parent_hash: Hash, view: u64) -> bool {
        match self.leader_for_view(parent_hash, view) {
            Some(leader) => leader == self.public_key(),
            None => false,
        }
    }

    fn leader_for_view(&self, parent_hash: Hash, view: u64) -> Option<NodePublicKey> {
        if let Ok(Some(parent)) = self.get_block(&parent_hash) {
            let leader = self.leader_at_block(&parent, view).unwrap();
            Some(leader.public_key)
        } else {
            if view > 1 {
                warn!(
                    "parent not found while determining leader for view {}",
                    view
                );
                return None;
            }
            let head_block = self.head_block();
            let leader = self.leader_at_block(&head_block, view).unwrap();
            Some(leader.public_key)
        }
    }

    fn committee_for_hash(&self, parent_hash: Hash) -> Result<Vec<NodePublicKey>> {
        let Ok(Some(parent)) = self.get_block(&parent_hash) else {
            // tracing::error!("parent block not found: {:?}", parent_hash);
            return Ok(Vec::new()); // return an empty vector instead of Err for graceful app-level error-handling
        };

        let parent_root_hash = parent.state_root_hash();

        let state = self.state.at_root(parent_root_hash.into());
        let executed_block = BlockHeader {
            number: parent.header.number + 1,
            ..Default::default()
        };

        let committee = state.get_stakers(executed_block)?;

        Ok(committee)
    }

    /// Process a NewView message
    pub fn new_view(&mut self, from: PeerId, new_view: NewView) -> Result<Option<NetworkMessage>> {
        info!(
            "Received new view for view: {:?} from: {:?}",
            new_view.view, from
        );

        if self.get_block(&new_view.qc.block_hash)?.is_none() {
            trace!("high_qc block does not exist for NewView. Attempting to fetch block via sync");
            self.sync.sync_from_probe()?;
            return Ok(None);
        }

        // Get the committee for the qc hash (should be highest?) for this view
        let committee: Vec<_> = self.committee_for_hash(new_view.qc.block_hash)?;
        // verify the sender's signature on the block hash
        let Some((index, public_key)) = committee
            .iter()
            .enumerate()
            .find(|&(_, &public_key)| public_key == new_view.public_key)
        else {
            debug!(
                "ignoring new view from unknown node (buffer?) - committee size is : {:?} hash is: {:?} high hash is: {:?}",
                committee.len(),
                new_view.qc.block_hash,
                self.high_qc.block_hash
            );
            return Ok(None);
        };

        new_view.verify(*public_key)?;

        // Update our high QC and view, even if we are not the leader of this view.
        self.update_high_qc_and_view(false, new_view.qc)?;

        let mut current_view = self.get_view()?;
        // if the vote is too old and does not count anymore
        if new_view.view < current_view {
            trace!(
                new_view.view,
                "Received a NewView which is too old for us, discarding. Our view is: {} and new_view is: {}",
                current_view,
                new_view.view
            );
            return Ok(None);
        }

        // The leader for this view should be chosen according to the parent of the highest QC
        // What happens when there are multiple QCs with different parents?
        // if we are not the leader of the round in which the vote counts
        if !self.are_we_leader_for_view(new_view.qc.block_hash, new_view.view) {
            trace!(new_view.view, "skipping new view, not the leader");
            return Ok(None);
        }

        let mut new_view_vote =
            self.new_views
                .entry(new_view.view)
                .or_insert_with(|| NewViewVote {
                    signatures: Vec::new(),
                    cosigned: bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE],
                    cosigned_weight: 0,
                    qcs: BTreeMap::new(),
                });

        let Ok(Some(parent)) = self.get_block(&new_view.qc.block_hash) else {
            return Err(anyhow!(
                "parent block not found: {:?}",
                new_view.qc.block_hash
            ));
        };
        let executed_block = BlockHeader {
            number: parent.header.number + 1,
            ..Default::default()
        };

        let mut supermajority = false;

        // if the vote is new, store it
        if !new_view_vote.cosigned[index] {
            new_view_vote.cosigned.set(index, true);
            new_view_vote.signatures.push(new_view.signature);

            let Ok(Some(parent)) = self.get_block(&new_view.qc.block_hash) else {
                return Err(anyhow!(
                    "parent block not found: {:?}",
                    new_view.qc.block_hash
                ));
            };
            // Update state to root pointed by voted block (in meantime it might have changed!)
            self.state.set_to_root(parent.state_root_hash().into());
            let Some(weight) = self.state.get_stake(new_view.public_key, executed_block)? else {
                return Err(anyhow!("vote from validator without stake"));
            };
            new_view_vote.cosigned_weight += weight.get();
            new_view_vote.qcs.insert(index, new_view.qc);

            supermajority = new_view_vote.cosigned_weight * 3
                > self.total_weight(&committee, executed_block) * 2;

            let num_signers = new_view_vote.signatures.len();

            trace!(
                num_signers,
                cosigned_weight = new_view_vote.cosigned_weight,
                supermajority,
                current_view,
                new_view.view,
                "storing vote for new view"
            );
            if supermajority {
                if current_view < new_view.view {
                    info!(
                        "forcibly updating view to {} as majority is ahead",
                        new_view.view
                    );
                    current_view = new_view.view;
                    self.set_view(current_view, false)?;
                }

                // if we are already in the round in which the vote counts and have reached supermajority we can propose a block
                if new_view.view == current_view {
                    // todo: the aggregate qc is an aggregated signature on the qcs, view and validator index which can be batch verified
                    let agg = self.aggregate_qc_from_indexes(
                        new_view.view,
                        &new_view_vote.qcs,
                        &new_view_vote.signatures,
                        new_view_vote.cosigned,
                    )?;

                    info!(
                        view = current_view,
                        "######### creating proposal block from new view"
                    );

                    // We now have a valid aggQC so can create early_block with it
                    self.early_proposal_assemble_at(Some(agg))?;

                    // as a future improvement, process the proposal before broadcasting it
                    return self.ready_for_block_proposal(None);

                    // we don't want to keep the collected votes if we proposed a new block
                    // we should remove the collected votes if we couldn't reach supermajority within the view
                }
            }
        }
        if supermajority {
            // Cleanup
            self.new_views.remove(&new_view.view);
        }

        Ok(None)
    }

    /// Returns (flag, outcome).
    /// flag is true if the transaction was newly added to the pool - ie. if it validated correctly and has not been seen before.
    pub fn new_transaction(
        &self,
        txn: VerifiedTransaction,
        from_broadcast: bool,
    ) -> Result<TxAddResult> {
        if self.db.contains_transaction(&txn.hash)? {
            debug!("Transaction {:?} already in mempool", txn.hash);
            return Ok(TxAddResult::Duplicate(txn.hash));
        }

        // Perform insertion under early state, if available
        let early_account = match self.early_proposal.read().as_ref() {
            Some((block, _, _, _, _)) => {
                let state = self.state.at_root(block.state_root_hash().into());
                state.get_account(txn.signer)?
            }
            _ => self.state.get_account(txn.signer)?,
        };

        let eth_chain_id = self.config.eth_chain_id;

        let validation_result = txn.tx.validate(
            &early_account,
            self.config.consensus.eth_block_gas_limit,
            self.config.consensus.gas_price.0,
            eth_chain_id,
        )?;
        if !validation_result.is_ok() {
            warn!(
                "Unable to validate txn with hash: {:?}, from: {:?}, nonce: {:?} : {:?}",
                txn.hash,
                txn.signer,
                txn.tx.nonce(),
                validation_result,
            );
            return Ok(TxAddResult::ValidationFailed(validation_result));
        }

        let txn_hash = txn.hash;

        let insert_result = self.transaction_pool.write().insert_transaction(
            txn.clone(),
            &early_account,
            from_broadcast,
        );
        if insert_result.was_added() {
            let _ = self.new_transaction_hashes.send(txn_hash);

            // Avoid cloning the transaction if there aren't any subscriptions to send it to.
            if self.new_transactions.receiver_count() != 0 {
                let _ = self.new_transactions.send(txn.clone());
            }
        }
        Ok(insert_result)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<VerifiedTransaction>> {
        Ok(match self.db.get_transaction(&hash)? {
            Some(tx) => Some(tx),
            None => self.transaction_pool.read().get_transaction(&hash).cloned(),
        })
    }

    pub fn get_transaction_receipt(&self, hash: &Hash) -> Result<Option<TransactionReceipt>> {
        let Some(block_hash) = self.db.get_block_hash_reverse_index(hash)? else {
            return Ok(None);
        };
        let block_receipts = self.db.get_transaction_receipts_in_block(&block_hash)?;
        Ok(block_receipts
            .into_iter()
            .find(|receipt| receipt.tx_hash == *hash))
    }

    fn update_high_qc_and_view(
        &mut self,
        from_agg: bool,
        new_high_qc: QuorumCertificate,
    ) -> Result<()> {
        let view = self.get_view()?;
        let Some(new_high_qc_block) = self.db.get_block(new_high_qc.block_hash.into())? else {
            // We don't set high_qc to a qc if we don't have its block.
            warn!("Recieved potential high QC but didn't have the corresponding block");
            return Ok(());
        };

        let new_high_qc_view = new_high_qc_block.view();

        if self.high_qc.block_hash == Hash::ZERO {
            trace!(
                "received high qc, self high_qc is currently uninitialized, setting to the new one."
            );
            self.db.set_high_qc(new_high_qc)?;
            self.high_qc = new_high_qc;
        } else {
            let current_high_qc_view = self
                .get_block(&self.high_qc.block_hash)?
                .ok_or_else(|| {
                    anyhow!("missing block corresponding to our high qc - this should never happen")
                })?
                .view();
            // If `from_agg` then we always release the lock because the supermajority has a different high_qc.
            if from_agg || new_high_qc_view > current_high_qc_view {
                trace!(
                    new_high_qc_view,
                    current_high_qc_view,
                    current_view = view,
                    "updating high qc"
                );
                self.db.set_high_qc(new_high_qc)?;
                self.high_qc = new_high_qc;
                if new_high_qc_view >= view {
                    self.set_view(new_high_qc_view + 1, false)?;
                }
            }
        }

        Ok(())
    }

    fn aggregate_qc_from_indexes(
        &self,
        view: u64,
        qcs: &BTreeMap<usize, QuorumCertificate>,
        signatures: &[BlsSignature],
        cosigned: BitArray,
    ) -> Result<AggregateQc> {
        assert_eq!(qcs.len(), signatures.len());

        Ok(AggregateQc {
            signature: BlsSignature::aggregate(signatures)?,
            cosigned,
            view,
            // Because qcs is a map from index to qc, this will
            // end up as a list in ascending order of index, which
            // is what we want to correspond with the way
            // batch_verify_agg_signature() will attempt to verify
            // them.
            qcs: qcs.values().cloned().collect::<Vec<QuorumCertificate>>(),
        })
    }

    fn qc_from_bits(
        &self,
        block_hash: Hash,
        signatures: &[BlsSignature],
        cosigned: BitArray,
        view: u64,
    ) -> QuorumCertificate {
        // we've already verified the signatures upon receipt of the responses so there's no need to do it again
        QuorumCertificate::new(signatures, cosigned, block_hash, view)
    }

    fn block_extends_from(&self, block: &Block, ancestor: &Block) -> Result<bool> {
        // todo: the block extends from another block through a chain of parent hashes and not qcs
        // make ticket for this
        let mut current = block.clone();
        while current.view() > ancestor.view() {
            let Some(next) = self.get_block(&current.parent_hash())? else {
                warn!(
                    "Missing block when traversing to find ancestor! Current parent hash: {:?} {:?}",
                    current.parent_hash(),
                    current
                );
                return Err(MissingBlockError::from(current.parent_hash()).into());
            };
            current = next;
        }

        Ok(current.view() == 0 || current.hash() == ancestor.hash())
    }

    fn check_safe_block(&mut self, proposal: &Block) -> Result<bool> {
        match proposal.agg {
            Some(ref agg_qc) => {
                let Some(highest_qc) = agg_qc.qcs.iter().max_by_key(|qc| qc.view) else {
                    return Ok(false);
                };
                let Some(qc_block) = self.get_block(&highest_qc.block_hash)? else {
                    trace!(
                        "could not get block the qc points to: {}",
                        highest_qc.block_hash
                    );
                    return Ok(false);
                };
                match self.block_extends_from(proposal, &qc_block) {
                    Ok(true) => {
                        self.check_and_commit(proposal)?;
                        Ok(true)
                    }
                    Ok(false) => {
                        trace!("block does not extend from parent");
                        Ok(false)
                    }
                    Err(e) => {
                        trace!(?e, "error checking block extension");
                        Ok(false)
                    }
                }
            }
            None => {
                let Some(qc_block) = self.get_block(&proposal.parent_hash())? else {
                    trace!(
                        "could not get block the qc points to: {}",
                        proposal.parent_hash()
                    );
                    return Ok(false);
                };
                if proposal.view() == 0 || proposal.view() == qc_block.view() + 1 {
                    self.check_and_commit(proposal)?;
                    Ok(true)
                } else {
                    trace!(
                        "block does not extend from parent, {} != {} + 1",
                        proposal.view(),
                        qc_block.view()
                    );
                    Ok(false)
                }
            }
        }
    }

    /// Check if a new proposal allows an older block to become finalized.
    /// Errors iff the proposal's parent is not known.
    fn check_and_commit(&mut self, proposal: &Block) -> Result<()> {
        // The condition for a block to be finalized is if there is a direct two-chain. From the paper:
        // Once a replica is convinced, it checks
        // if a two-chain is formed over the top of the parent of the
        // block pointed by the highQC (the first chain in the two-chain
        // formed has to be a one-direct chain in case of pipelined Fast-
        // HotStuff). Then a replica can safely commit the parent of the
        // block pointed by the highQC.

        let Some(qc_block) = self.get_block(&proposal.parent_hash())? else {
            warn!("missing qc block when checking whether to finalize!");
            return Err(MissingBlockError::from(proposal.parent_hash()).into());
        };

        // If we don't have the parent (e.g. genesis, or pruned node), we can't finalize, so just exit
        let Some(qc_parent) = self.get_block(&qc_block.parent_hash())? else {
            warn!("missing qc parent block when checking whether to finalize!");
            return Ok(());
        };

        // If we have a one-direct chain, we can finalize the parent regardless of the proposal's view number
        if qc_parent.view() + 1 == qc_block.view() {
            self.finalize_block(qc_parent)?;
        } else {
            warn!(
                "Cannot finalize block {} with view {} and number {} because of child {} with view {} and number {}",
                qc_parent.hash(),
                qc_parent.view(),
                qc_parent.number(),
                qc_block.hash(),
                qc_block.view(),
                qc_block.number()
            );
        }

        Ok(())
    }

    /// Saves the finalized tip view, and runs all hooks for the newly finalized block
    fn finalize_block(&mut self, block: Block) -> Result<()> {
        trace!(
            "Finalizing block {} at view {} num {}",
            block.hash(),
            block.view(),
            block.number()
        );

        let mut current = block.clone();
        let finalized_view = self.get_finalized_view()?;
        let mut new_missed_views = VecDeque::new();
        while current.view() > finalized_view {
            let parent = self.get_block(&current.parent_hash())?.ok_or_else(|| {
                anyhow!(format!("missing block parent {}", &current.parent_hash()))
            })?;
            let state_at = self.state.at_root(parent.state_root_hash().into());
            let block_header = BlockHeader {
                view: parent.header.view,
                number: parent.header.number,
                ..Default::default()
            };
            for view in (parent.view() + 1..current.view()).rev() {
                if let Ok(leader) = state_at.leader(view, block_header) {
                    if view == parent.view() + 1 {
                        trace!(
                            view,
                            id = &leader.as_bytes()[..3],
                            "~~~~~~~~~~> skipping reorged"
                        );
                    } else {
                        new_missed_views.push_front((view, leader)); // ensure new_missed_views in ascending order
                    }
                }
            }
            current = parent;
        }
        let max_missed_view_age = self.config.max_missed_view_age;
        let (extended, pruned, min_view) = {
            let mut history_guard = self.state.view_history.write();
            let extended = history_guard.append_history(&mut new_missed_views)?;
            let min_view = history_guard.min_view;
            let pruned = history_guard.prune_history(block.view(), max_missed_view_age)?;
            if min_view != history_guard.min_view {
                self.db
                    .set_min_view_of_view_history(history_guard.min_view)?;
            }
            // the following code is only for logging and can be commented out
            if extended || pruned {
                trace!(
                    view = self.get_view()?,
                    finalized = block.view(),
                    history = display(&*history_guard),
                    "~~~~~~~~~~> current"
                );
            }
            (extended, pruned, min_view)
        };
        //TODO(jailing): do not update the db on every finalization to avoid impact on block times
        if extended {
            for (view, leader) in new_missed_views.iter().rev() {
                self.db.extend_view_history(*view, leader.as_bytes())?;
            }
        }
        if pruned {
            self.db.prune_view_history(min_view)?;
        }
        self.state.finalized_view = block.view();

        self.set_finalized_view(block.view())?;

        let receipts = self.db.get_transaction_receipts_in_block(&block.hash())?;

        for (destination_shard, intershard_call) in blockhooks::get_cross_shard_messages(&receipts)?
        {
            self.message_sender.send_message_to_shard(
                destination_shard,
                InternalMessage::IntershardCall(intershard_call),
            )?;
        }

        if self.config.consensus.is_main {
            // Main shard will join all new shards
            for new_shard_id in blockhooks::get_launch_shard_messages(&receipts)? {
                self.message_sender
                    .send_message_to_coordinator(InternalMessage::LaunchShard(new_shard_id))?;
            }

            // Main shard also hosts the shard registry, so will be notified of newly established
            // links. Notify corresponding shard nodes of said links, if any
            for (from, to) in blockhooks::get_link_creation_messages(&receipts)? {
                self.message_sender
                    .send_message_to_shard(to, InternalMessage::LaunchLink(from))?;
            }
        }

        if self.block_is_first_in_epoch(block.number())
            && !block.is_genesis()
            && self.config.do_checkpoints
            && self.epoch_is_checkpoint(self.epoch_number(block.number()))
            && let Some(checkpoint_path) = self.db.get_checkpoint_dir()?
        {
            let parent = self
                .db
                .get_block(block.parent_hash().into())?
                .ok_or(anyhow!(
                    "Trying to checkpoint block, but we don't have its parent"
                ))?;
            let transactions: Vec<SignedTransaction> = block
                .transactions
                .iter()
                .map(|txn_hash| {
                    let tx = self.db.get_transaction(txn_hash)?.ok_or(anyhow!(
                        "failed to fetch transaction {} for checkpoint parent {}",
                        txn_hash,
                        parent.hash()
                    ))?;
                    Ok::<_, anyhow::Error>(tx.tx)
                })
                .collect::<Result<Vec<SignedTransaction>>>()?;

            self.message_sender.send_message_to_coordinator(
                InternalMessage::ExportBlockCheckpoint(
                    Box::new(block),
                    transactions,
                    Box::new(parent),
                    self.db.state_trie()?.clone(),
                    self.state.view_history.read().clone(),
                    checkpoint_path,
                ),
            )?;
        }

        Ok(())
    }

    /// Trigger a checkpoint, for debugging.
    /// Returns (file_name, block_hash). At some time after you call this function, hopefully a checkpoint will end up in the file
    pub fn checkpoint_at(&self, block_number: u64) -> Result<(String, String)> {
        let block = self
            .get_canonical_block_by_number(block_number)?
            .ok_or(anyhow!("No such block number {block_number}"))?;
        let parent = self
            .db
            .get_block(block.parent_hash().into())?
            .ok_or(anyhow!(
                "Trying to checkpoint block, but we don't have its parent"
            ))?;
        let transactions: Vec<SignedTransaction> = block
            .transactions
            .iter()
            .map(|txn_hash| {
                let tx = self.db.get_transaction(txn_hash)?.ok_or(anyhow!(
                    "failed to fetch transaction {} for checkpoint parent {}",
                    txn_hash,
                    parent.hash()
                ))?;
                Ok::<_, anyhow::Error>(tx.tx)
            })
            .collect::<Result<Vec<SignedTransaction>>>()?;
        let checkpoint_dir = self
            .db
            .get_checkpoint_dir()?
            .ok_or(anyhow!("No checkpoint directory configured"))?;
        let file_name = db::get_checkpoint_filename(checkpoint_dir.clone(), &block)?;
        let hash = block.hash();
        let missed_view_age = self.config.max_missed_view_age; //constants::MISSED_VIEW_WINDOW;
        // after loading the checkpoint we will need the leader of its parent block, but also
        // have to include the potential missed views between the checkpoint block and its parent
        let view_history =
            self.state
                .view_history
                .read()
                .new_at(parent.view(), block.view(), missed_view_age);
        info!(
            view = self.get_view()?,
            ckpt_parent_view = parent.view(),
            ckpt_block_view = block.view(),
            view_history = display(&view_history),
            "~~~~~~~~~~> saving checkpoint in current"
        );
        self.message_sender
            .send_message_to_coordinator(InternalMessage::ExportBlockCheckpoint(
                Box::new(block),
                transactions,
                Box::new(parent),
                self.db.state_trie()?,
                view_history,
                checkpoint_dir,
            ))?;
        Ok((file_name.display().to_string(), hash.to_string()))
    }

    /// Check the validity of a block. Returns `Err(_, true)` if this block could become valid in the future and
    /// `Err(_, false)` if this block could never be valid.
    fn check_block(&self, block: &Block, during_sync: bool) -> Result<()> {
        block.verify_hash()?;

        if block.view() == 0 {
            // We only check a block if we receive it from an external source. We obviously already have the genesis
            // block, so we aren't ever expecting to receive it.
            return Err(anyhow!("tried to check genesis block"));
        }

        let Some(parent) = self.get_block(&block.parent_hash())? else {
            warn!(
                "Missing parent block while trying to check validity of block number {}",
                block.number()
            );
            return Err(MissingBlockError::from(block.parent_hash()).into());
        };

        let finalized_view = self.get_finalized_view()?;
        let Some(finalized_block) = self.get_block_by_view(finalized_view)? else {
            return Err(MissingBlockError::from(finalized_view).into());
        };
        if block.view() < finalized_block.view() {
            return Err(anyhow!(
                "block is too old: view is {} but we have finalized {}",
                block.view(),
                finalized_block.view()
            ));
        }

        // Derive the proposer from the block's view
        let Some(proposer) = self.leader_at_block(&parent, block.view()) else {
            return Err(anyhow!(
                "Failed to find leader. Block number {}, Parent number {}",
                block.number(),
                parent.number(),
            ));
        };

        // Verify the proposer's signature on the block
        let verified = proposer
            .public_key
            .verify(block.hash().as_bytes(), block.signature());

        let committee = self
            .state
            .at_root(parent.state_root_hash().into())
            .get_stakers(block.header)?;

        if verified.is_err() {
            info!(?block, "Unable to verify block = ");
            return Err(anyhow!(
                "invalid block signature found! block hash: {:?} block view: {:?} committee len {:?}",
                block.hash(),
                block.view(),
                committee.len()
            ));
        }

        // Check if the co-signers of the block's QC represent the supermajority.
        self.check_quorum_in_bits(
            &block.header.qc.cosigned,
            &committee,
            parent.state_root_hash(),
            block,
        )?;

        // Verify the block's QC signature - note the parent should be the committee the QC
        // was signed over.
        self.verify_qc_signature(&block.header.qc, committee.clone())?;
        if let Some(agg) = &block.agg {
            // Check if the signers of the block's aggregate QC represent the supermajority
            self.check_quorum_in_indices(
                &agg.cosigned,
                &committee,
                parent.state_root_hash(),
                block,
            )?;
            // Verify the aggregate QC's signature
            self.batch_verify_agg_signature(agg, &committee)?;
        }

        // Retrieve the highest among the aggregated QCs and check if it equals the block's QC.
        let block_high_qc = self.get_high_qc_from_block(block)?;
        let Some(block_high_qc_block) = self.get_block(&block_high_qc.block_hash)? else {
            warn!("missing finalized block");
            return Err(MissingBlockError::from(block_high_qc.block_hash).into());
        };
        // Prevent the creation of forks from the already committed chain
        if block_high_qc_block.view() < finalized_block.view() {
            warn!(
                "invalid block - high QC view is {} while finalized is {}. Our High QC: {}, block: {:?}",
                block_high_qc_block.view(),
                finalized_block.view(),
                self.high_qc,
                block
            );
            return Err(anyhow!(
                "invalid block - high QC view is {} while finalized is {}",
                block_high_qc_block.view(),
                finalized_block.view()
            ));
        }

        // This block's timestamp must be greater than or equal to the parent block's timestamp.
        if block.timestamp() < parent.timestamp() {
            return Err(anyhow!("timestamp decreased from parent"));
        }

        // This block's timestamp should be at most `self.allowed_timestamp_skew` away from the current time. Note this
        // can be either forwards or backwards in time.
        let difference = block
            .timestamp()
            .elapsed()
            .unwrap_or_else(|err| err.duration());
        if !during_sync && difference > self.config.allowed_timestamp_skew {
            return Err(anyhow!(
                "timestamp difference for block {} greater than allowed skew: {difference:?}",
                block.view()
            ));
        }

        // Blocks must be in sequential order
        if block.header.number != parent.header.number + 1 {
            return Err(anyhow!(
                "block number is not sequential: {} != {} + 1",
                block.header.number,
                parent.header.number
            ));
        }

        if !self.block_extends_from(block, &finalized_block)? {
            warn!(
                "invalid block {:?}, does not extend finalized block {:?} our head is {:?}",
                block,
                finalized_block,
                self.head_block()
            );

            return Err(anyhow!(
                "invalid block, does not extend from finalized block"
            ));
        }
        Ok(())
    }

    // Receives availability and passes it on to the block store.
    pub fn receive_block_availability(
        &mut self,
        from: PeerId,
        _availability: &Option<Vec<BlockStrategy>>,
    ) -> Result<()> {
        trace!("Received block availability from {:?}", from);
        Ok(()) // FIXME: Stub
    }

    // Checks for the validity of a block and adds it to our block store if valid.
    // Returns true when the block is valid and newly seen and false otherwise.
    // Optionally returns a proposal that should be sent as the result of this newly received block. This occurs when
    // the node has buffered votes for a block it doesn't know about and later receives that block, resulting in a new
    // block proposal.
    pub fn receive_block(&mut self, from: PeerId, proposal: Proposal) -> Result<Option<Proposal>> {
        trace!(
            "received block: {} number: {}, view: {}",
            proposal.hash(),
            proposal.number(),
            proposal.view()
        );
        let result = self.proposal(from, proposal, true)?;
        // Processing the received block can either result in:
        // * A `Proposal`, if we have buffered votes for this block which form a supermajority, meaning we can
        // propose the next block.
        // * A `Vote`, if the block is valid and we are in the proposed block's committee. However, this block
        // occured in the past, meaning our vote is no longer valid.
        // Therefore, we filter the result to only include `Proposal`s. This avoids us sending useless `Vote`s
        // to the network while syncing.
        Ok(result.and_then(|(_, message)| message.into_proposal()))
    }

    fn add_block(&self, from: Option<PeerId>, block: Block) -> Result<()> {
        let hash = block.hash();
        debug!(?from, ?hash, ?block.header.view, ?block.header.number, "added block");
        let _ = self.new_blocks.send(block.header);
        self.db.insert_block(&block)?;
        Ok(())
    }

    fn block_is_first_in_epoch(&self, number: u64) -> bool {
        number.is_multiple_of(self.config.consensus.blocks_per_epoch)
    }

    fn epoch_number(&self, block_number: u64) -> u64 {
        // This will need additonal tracking if we ever allow blocks_per_epoch to be changed
        block_number / self.config.consensus.blocks_per_epoch
    }

    fn epoch_is_checkpoint(&self, epoch_number: u64) -> bool {
        epoch_number.is_multiple_of(self.config.consensus.epochs_per_checkpoint)
    }

    fn vote_from_block(&self, block: &Block) -> Vote {
        Vote::new(
            self.secret_key,
            block.hash(),
            self.secret_key.node_public_key(),
            block.view(),
        )
    }

    fn get_high_qc_from_block(&self, block: &Block) -> Result<QuorumCertificate> {
        let Some(agg) = &block.agg else {
            return Ok(block.header.qc);
        };

        let high_qc = self.get_highest_from_agg(agg)?;

        if block.header.qc != high_qc {
            return Err(anyhow!("qc mismatch"));
        }

        Ok(block.header.qc)
    }

    pub fn get_block(&self, key: &Hash) -> Result<Option<Block>> {
        self.db.get_block(key.into())
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        self.db.get_block(BlockFilter::View(view))
    }

    pub fn get_canonical_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        self.db.get_block(BlockFilter::Height(number))
    }

    fn set_finalized_view(&self, view: u64) -> Result<()> {
        self.db.set_finalized_view(view)
    }

    pub fn get_finalized_view(&self) -> Result<u64> {
        Ok(self.db.get_finalized_view()?.unwrap_or_else(|| {
            warn!("no finalised view found in table. Defaulting to 0");
            0
        }))
    }

    fn set_view(&self, view: u64, voted: bool) -> Result<()> {
        if self.db.set_view(view, voted)? {
            *self.view_updated_at.write() = SystemTime::now();
        } else {
            warn!(
                "Tried to set view to lower or same value - this is incorrect. value: {}",
                view
            );
        }
        Ok(())
    }

    pub fn get_view(&self) -> Result<u64> {
        Ok(self.db.get_view()?.unwrap_or_else(|| {
            warn!("no view found in table. Defaulting to 0");
            0
        }))
    }

    /// Calculate how long we should wait before timing out for this view
    pub fn exponential_backoff_timeout(&self, view: u64) -> u64 {
        let view_difference = view.saturating_sub(self.high_qc.view) as u32;
        // in view N our highQC is the one we obtained in view N-1 (or before) and its view is N-2 (or lower)
        // in other words, the current view is always at least 2 views ahead of the highQC's view
        // i.e. to get `consensus_timeout_ms * 2^0` we have to subtract 2 from `view_difference`
        let consensus_timeout = self.config.consensus.consensus_timeout.as_millis() as f32;
        (consensus_timeout
            * (EXPONENTIAL_BACKOFF_TIMEOUT_MULTIPLIER)
                .powi(view_difference.saturating_sub(2) as i32))
        .floor() as u64
    }

    /// Find minimum number of views which could have passed by in the given time difference.
    /// We assume that no valid proposals have been finalised in this time.
    pub fn minimum_views_in_time_difference(
        time_difference: Duration,
        consensus_timeout: Duration,
    ) -> u64 {
        let normalised_time_difference =
            (time_difference.as_millis() / consensus_timeout.as_millis()) as f32;
        let mut views = 0;
        let mut total = 0.0;
        loop {
            total += (EXPONENTIAL_BACKOFF_TIMEOUT_MULTIPLIER).powi(views);
            if total > normalised_time_difference {
                break;
            }
            views += 1;
        }
        views as u64
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    pub fn state_at(&self, number: u64) -> Result<Option<State>> {
        Ok(self
            .db
            .get_block(BlockFilter::Height(number))?
            .map(|block| self.state.at_root(block.state_root_hash().into())))
    }

    pub fn try_get_state_at(&self, number: u64) -> Result<State> {
        self.state_at(number)?
            .ok_or_else(|| anyhow!("No block at height {number}"))
    }

    fn get_highest_from_agg(&self, agg: &AggregateQc) -> Result<QuorumCertificate> {
        agg.qcs
            .iter()
            .max_by_key(|qc| qc.view)
            .copied()
            .ok_or_else(|| anyhow!("no qcs in agg"))
    }

    pub fn replay_proposal(
        &mut self,
        block: Block,
        transactions: Vec<SignedTransaction>,
        parent_state: Hash,
    ) -> Result<()> {
        let prev_root_hash = self.state.root_hash()?;
        self.state.set_to_root(parent_state.into());
        let stakers = self.state.get_stakers(block.header)?;
        self.execute_block(None, &block, transactions, stakers.as_slice(), true)?;
        // restore previous state
        self.state.set_to_root(prev_root_hash.into());
        Ok(())
    }

    fn verify_qc_signature(
        &self,
        qc: &QuorumCertificate,
        public_keys: Vec<NodePublicKey>,
    ) -> Result<()> {
        let len = public_keys.len();
        match qc.verify(public_keys) {
            true => Ok(()),
            false => {
                warn!(
                    "invalid qc signature found when verifying! Public keys: {:?}. QC: {}",
                    len, qc
                );
                Err(anyhow!("invalid qc signature found!"))
            }
        }
    }

    fn batch_verify_agg_signature(
        &self,
        agg: &AggregateQc,
        committee: &[NodePublicKey],
    ) -> Result<()> {
        let mut public_keys = Vec::new();
        for (index, bit) in agg.cosigned.iter().enumerate() {
            if *bit {
                public_keys.push(*committee.get(index).unwrap());
            }
        }

        let messages: Vec<_> = agg
            .qcs
            .iter()
            .zip(public_keys.iter())
            .map(|(qc, key)| {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(qc.compute_hash().as_bytes());
                bytes.extend_from_slice(&key.as_bytes());
                bytes.extend_from_slice(&agg.view.to_be_bytes());
                bytes
            })
            .collect();
        let messages: Vec<_> = messages.iter().map(|m| m.as_slice()).collect();

        verify_messages(agg.signature, &messages, &public_keys)?;
        Ok(())
    }

    // TODO: Consider if these checking functions should be implemented at the deposit contract level instead?

    fn check_quorum_in_bits(
        &self,
        cosigned: &BitSlice,
        committee: &[NodePublicKey],
        parent_state_hash: Hash,
        block: &Block,
    ) -> Result<()> {
        let parent_state = self.state.at_root(parent_state_hash.into());

        let (total_weight, cosigned_sum) = committee
            .iter()
            .enumerate()
            .map(|(i, public_key)| {
                (
                    i,
                    parent_state
                        .get_stake(*public_key, block.header)
                        .unwrap()
                        .unwrap()
                        .get(),
                )
            })
            .fold((0, 0), |(total_weight, cosigned_sum), (i, stake)| {
                (
                    total_weight + stake,
                    cosigned_sum
                        + if cosigned[i] {
                            stake
                        } else {
                            Default::default()
                        },
                )
            });

        if cosigned_sum * 3 <= total_weight * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    fn check_quorum_in_indices(
        &self,
        signers: &BitSlice,
        committee: &[NodePublicKey],
        parent_state_hash: Hash,
        block: &Block,
    ) -> Result<()> {
        let parent_state = self.state.at_root(parent_state_hash.into());

        let cosigned_sum: u128 = signers
            .iter()
            .enumerate()
            .map(|(i, bit)| {
                if *bit {
                    let public_key = committee.get(i).unwrap();
                    let stake = parent_state
                        .get_stake(*public_key, block.header)
                        .unwrap()
                        .unwrap();
                    stake.get()
                } else {
                    0
                }
            })
            .sum();

        if cosigned_sum * 3 <= self.total_weight(committee, block.header) * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    pub fn leader_at_block(&self, block: &Block, view: u64) -> Option<Validator> {
        let state_at = self.state.at_root(block.state_root_hash().into());
        Self::leader_at_state(&state_at, block, view)
    }

    pub fn leader_at_state(state: &State, block: &Block, view: u64) -> Option<Validator> {
        let executed_block = BlockHeader {
            // we need to set the (parent) block's view at which we call the jailing
            // precompile otherwise we won't know if we must use the node's history
            // or the checkpoint's history gradually extended during state-syncing
            view: block.header.view + 1,
            number: block.header.number + 1,
            ..Default::default()
        };
        let Ok(public_key) = state.leader(view, executed_block) else {
            return None;
        };

        let Ok(Some(peer_id)) = state.get_peer_id(public_key) else {
            return None;
        };

        Some(Validator {
            public_key,
            peer_id,
        })
    }

    fn total_weight(&self, committee: &[NodePublicKey], executed_block: BlockHeader) -> u128 {
        committee
            .iter()
            .map(|&pub_key| {
                let stake = self
                    .state
                    .get_stake(pub_key, executed_block)
                    .unwrap()
                    .unwrap();
                stake.get()
            })
            .sum()
    }

    /// Deal with the fork to this block. The block is assumed to be valid to switch to.
    /// Set the current head block to the parent of the proposed block,
    /// This will make it so the block is ready to become the new head
    fn deal_with_fork(&mut self, block: &Block) -> Result<()> {
        // To generically deal with forks where the proposed block could be at any height, we
        // Find the common ancestor (backward) of the head block and the new block
        // Then, revert the blocks from the head block to the common ancestor
        // Then, apply the blocks (forward) from the common ancestor to the parent of the new block
        let mut head = self.head_block();
        let mut head_height = head.number();
        let mut proposed_block = block.clone();
        let mut proposed_block_height = block.number();
        trace!(
            "Dealing with fork: between head block {} (height {}), and proposed block {} (height {})",
            head.hash(),
            head_height,
            proposed_block.hash(),
            proposed_block_height
        );

        // Need to make sure both pointers are at the same height
        while head_height > proposed_block_height {
            trace!("Stepping back head block pointer");
            head = self.get_block(&head.parent_hash())?.unwrap();
            head_height = head.number();
        }

        while proposed_block_height > head_height {
            trace!("Stepping back proposed block pointer");
            proposed_block = self.get_block(&proposed_block.parent_hash())?.unwrap();
            proposed_block_height = proposed_block.number();
        }

        // We now have both hash pointers at the same height, we can walk back until they are equal.
        while head.hash() != proposed_block.hash() {
            trace!("Stepping back both pointers");
            head = self.get_block(&head.parent_hash())?.unwrap();
            proposed_block = self.get_block(&proposed_block.parent_hash())?.unwrap();
        }
        trace!(
            "common ancestor found: block number: {}, view: {}, hash: {}",
            head.number(),
            head.view(),
            head.hash()
        );

        // Now, we want to revert the blocks until the head block is the common ancestor
        while self.head_block().hash() != head.hash() {
            let head_block = self.head_block();
            let parent_block = self.get_block(&head_block.parent_hash())?.ok_or_else(|| {
                anyhow!(
                    "missing block parent when reverting blocks: {}",
                    head_block.parent_hash()
                )
            })?;

            if head_block.header.view == 0 {
                panic!("genesis block is not supposed to be reverted");
            }

            trace!(
                "Reverting block number: {}, view: {}, hash: {}",
                head_block.number(),
                head_block.view(),
                head_block.hash()
            );
            // block store doesn't require anything, it will just hold blocks that may now be invalid

            // State is easily set - must be to the parent block, though
            trace!(
                "Setting state to: {} aka block: number: {}, view: {}, hash: {}",
                parent_block.state_root_hash(),
                parent_block.number(),
                parent_block.view(),
                parent_block.hash()
            );
            self.state
                .set_to_root(parent_block.state_root_hash().into());

            // block transactions need to be removed from self.transactions and re-injected
            let mut pool = self.transaction_pool.write();
            for tx_hash in &head_block.transactions {
                let orig_tx = self.db.get_transaction(tx_hash)?.unwrap();

                // Insert this unwound transaction back into the transaction pool.
                let account = self.state.get_account(orig_tx.signer)?;
                pool.insert_transaction(orig_tx, &account, true);
            }

            // this block is no longer in the main chain
            self.db.mark_block_as_non_canonical(head_block.hash())?;
        }

        // Now, we execute forward from the common ancestor to the new block parent which can
        // be required in rare cases.
        // We have the chain of blocks from the ancestor upwards to the proposed block via walking back.
        // We also keep track of the hash of the block of the previous iteration of this loop, to detect infinite loops
        // and give up.
        let mut last_block = block.hash();
        while self.head_block().hash() != block.parent_hash() {
            trace!("Advancing the head block to prepare for proposed block fork.");
            let head_block_for_log = self.head_block();
            trace!(
                "Head block number: {}, view: {}, hash: {}",
                head_block_for_log.number(),
                head_block_for_log.view(),
                head_block_for_log.hash()
            );
            trace!("desired block hash: {}", block.parent_hash());

            let desired_block_height = self.head_block().number() + 1;
            // Pointer to parent of proposed block
            let mut block_pointer = self
                .get_block(&block.parent_hash())?
                .ok_or_else(|| anyhow!("missing block when advancing head block pointer"))?;

            if block_pointer.header.number < desired_block_height {
                panic!("block height mismatch when advancing head block pointer");
            }

            // Update pointer to be the next block in the proposed block's chain which the node's chain has not yet executed
            while block_pointer.header.number != desired_block_height {
                block_pointer = self
                    .get_block(&block_pointer.parent_hash())?
                    .ok_or_else(|| anyhow!("missing block when advancing head block pointer"))?;
            }

            if block_pointer.hash() == last_block {
                return Err(anyhow!("entered loop while dealing with fork"));
            }
            last_block = block_pointer.hash();

            // We now have the block pointer at the desired height, we can apply it.
            trace!(
                "Fork execution of block number: {}, view: {}, hash: {}",
                block_pointer.number(),
                block_pointer.view(),
                block_pointer.hash()
            );
            let transactions = block_pointer.transactions.clone();
            let transactions = transactions
                .iter()
                .map(|tx_hash| self.db.get_transaction(tx_hash).unwrap().unwrap().tx)
                .collect();
            let parent = self
                .get_block(&block_pointer.parent_hash())?
                .ok_or_else(|| anyhow!("missing parent"))?;
            let committee: Vec<_> = self
                .state
                .at_root(parent.state_root_hash().into())
                .get_stakers(block_pointer.header)?;
            self.execute_block(None, &block_pointer, transactions, &committee, false)?;
        }

        Ok(())
    }

    fn execute_block(
        &mut self,
        from: Option<PeerId>,
        block: &Block,
        transactions: Vec<SignedTransaction>,
        committee: &[NodePublicKey],
        during_sync: bool,
    ) -> Result<()> {
        debug!("Executing block: {:?}", block.header);

        let parent = self
            .get_block(&block.parent_hash())?
            .ok_or_else(|| anyhow!("missing parent block when executing block!"))?;

        if !transactions.is_empty() {
            trace!("applying {} transactions to state", transactions.len());
        }

        {
            // Early return if it is safe to fast-forward
            let mut receipts_cache = self.receipts_cache.lock();
            if receipts_cache.hash == block.receipts_root_hash()
                && from.is_some_and(|peer_id| peer_id == self.peer_id())
            {
                debug!(
                    "fast-forward self-proposal view {} block number {}",
                    block.header.view, block.header.number
                );

                let mut block_receipts = Vec::new();

                for (tx_index, txn_hash) in block.transactions.iter().enumerate() {
                    let (receipt, addresses) = receipts_cache
                        .remove(txn_hash)
                        .expect("receipt cached during proposal assembly");

                    // Recover set of receipts
                    block_receipts.push((receipt, tx_index));

                    // Apply 'touched-address' from cache
                    for address in addresses {
                        self.db.add_touched_address(address, *txn_hash)?;
                    }
                }
                // fast-forward state
                self.state.set_to_root(block.state_root_hash().into());

                // broadcast/commit receipts
                return self.broadcast_commit_receipts(from, block, block_receipts);
            };
        }

        let mut verified_txns = Vec::new();
        {
            // Pool is write-lock here and has to be dropped after this scope
            let mut pool = self.transaction_pool.write();
            pool.update_with_state(&self.state);

            let fork = self.state.forks.get(block.header.number);

            // We re-inject any missing Intershard transactions (or really, any missing
            // transactions) from our mempool. If any txs are unavailable in both the
            // message or locally, the proposal cannot be applied
            for (idx, tx_hash) in block.transactions.iter().enumerate() {
                // Prefer to insert verified txn from pool. This is faster.
                let txn = match pool.get_transaction(tx_hash) {
                    Some(txn) => txn.clone(),
                    _ => match transactions.get(idx) {
                        Some(sig_txn) => {
                            let Ok(verified) = sig_txn.clone().verify() else {
                                warn!("Unable to verify included transaction in given block!");
                                return Ok(());
                            };
                            if verified.hash != *tx_hash {
                                warn!(
                                    "Computed txn hash doesn't match the hash provided in the given block!"
                                );
                                return Ok(());
                            }

                            // bypass this check during sync - since the txn has already been executed
                            if fork.check_minimum_gas_price && !during_sync {
                                let Ok(acc) = self.state.get_account(verified.signer) else {
                                    warn!(
                                        "Sender doesn't exist in recovered transaction from given block!"
                                    );
                                    return Ok(());
                                };

                                let Ok(ValidationOutcome::Success) = sig_txn.validate(
                                    &acc,
                                    self.config.consensus.eth_block_gas_limit,
                                    self.config.consensus.gas_price.0,
                                    self.config.eth_chain_id,
                                ) else {
                                    warn!(
                                        "Transaction recovered from given block failed to validate!"
                                    );
                                    return Ok(());
                                };
                            }
                            verified
                        }
                        None => {
                            warn!(
                                "Proposal {} at view {} referenced a transaction {} that was neither included in the broadcast nor found locally - cannot apply block",
                                block.hash(),
                                block.view(),
                                tx_hash
                            );
                            return Ok(());
                        }
                    },
                };
                verified_txns.push(txn);
            }
        }

        let mut block_receipts = Vec::new();
        let mut cumulative_gas_used = EvmGas(0);
        let mut receipts_trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
        let mut transactions_trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
        let mut cumulative_gas_fee = 0_u128;

        let transaction_hashes = verified_txns
            .iter()
            .map(|tx| format!("{:?}", tx.hash))
            .join(",");

        let mut touched_addresses = vec![];
        for (tx_index, txn) in verified_txns.iter().enumerate() {
            self.new_transaction(txn.clone(), true)?;
            let tx_hash = txn.hash;
            let mut inspector = TouchedAddressInspector::default();
            let result = Self::apply_transaction_at(
                &mut self.state,
                txn.clone(),
                block.header,
                &mut inspector,
                self.config.enable_ots_indices,
            )?
            .ok_or_else(|| anyhow!("proposed transaction failed to execute"))?;
            self.transaction_pool.write().mark_executed(txn);
            for address in inspector.touched {
                touched_addresses.push((address, tx_hash));
            }

            let gas_used = result.gas_used();
            cumulative_gas_used += gas_used;

            if cumulative_gas_used > block.gas_limit() {
                warn!("Cumulative gas used by executing transactions exceeded block limit!");
                return Ok(());
            }

            let gas_fee = gas_used.0 as u128 * txn.tx.gas_price_per_evm_gas();
            cumulative_gas_fee = cumulative_gas_fee
                .checked_add(gas_fee)
                .ok_or_else(|| anyhow!("Overflow occurred in cumulative gas fee calculation"))?;

            let receipt = Self::create_txn_receipt(result, tx_hash, tx_index, cumulative_gas_used);

            let receipt_hash = receipt.compute_hash();

            debug!(
                "During execution in view: {}, transaction with hash: {:?} produced receipt: {:?}, receipt hash: {:?}",
                self.get_view()?,
                tx_hash,
                receipt,
                receipt_hash
            );
            receipts_trie.insert(receipt_hash.as_bytes(), receipt_hash.as_bytes())?;

            transactions_trie.insert(tx_hash.as_bytes(), tx_hash.as_bytes())?;

            debug!(?receipt, "applied transaction {:?}", receipt);
            block_receipts.push((receipt, tx_index));
        }

        self.db.with_sqlite_tx(|sqlite_tx| {
            for txn in &verified_txns {
                self.db
                    .insert_transaction_with_db_tx(sqlite_tx, &txn.hash, txn)?;
            }
            for (addr, txn_hash) in touched_addresses {
                self.db
                    .add_touched_address_with_db_tx(sqlite_tx, addr, txn_hash)?;
            }
            Ok(())
        })?;

        if cumulative_gas_used != block.gas_used() {
            warn!(
                "Cumulative gas used by executing all transactions: {cumulative_gas_used} is different than the one provided in the block: {}",
                block.gas_used()
            );
            return Ok(());
        }

        let receipts_root_hash: Hash = receipts_trie.root_hash()?.into();
        if block.header.receipts_root_hash != receipts_root_hash {
            warn!(
                "Block number: {}, Receipt root mismatch. Specified in block: {} vs computed: {}, txn_hashes: {}",
                block.number(),
                block.header.receipts_root_hash,
                receipts_root_hash,
                transaction_hashes
            );
            return Ok(());
        }

        let transactions_root_hash: Hash = transactions_trie.root_hash()?.into();
        if block.header.transactions_root_hash != transactions_root_hash {
            warn!(
                "Block number: {}, Transactions root mismatch. Specified in block: {} vs computed: {}, txn_hashes: {}",
                block.number(),
                block.header.transactions_root_hash,
                transactions_root_hash,
                transaction_hashes
            );
            return Ok(());
        }

        let mut state = self.state.clone();
        self.apply_proposal_to_state(&mut state, block, &parent, committee, cumulative_gas_fee)?;
        self.state = state;

        if self.state.root_hash()? != block.state_root_hash() {
            error!(
                "State root hash mismatch! Our state hash: {}, block hash: {:?} block prop: {:?}",
                self.state.root_hash()?,
                block.state_root_hash(),
                block,
            );
            return Err(anyhow!(
                "state root hash mismatch, expected: {:?}, actual: {:?}",
                block.state_root_hash(),
                self.state.root_hash()
            ));
        }

        self.broadcast_commit_receipts(from, block, block_receipts)
    }

    fn apply_proposal_to_state(
        &self,
        state: &mut State,
        block: &Block,
        parent: &Block,
        committee: &[NodePublicKey],
        cumulative_gas_fee: u128,
    ) -> Result<()> {
        // Apply the rewards of previous round
        let proposer = self.leader_at_block(parent, block.view()).unwrap();
        Self::apply_rewards_late_at(
            parent,
            state,
            &self.config.consensus,
            committee,
            proposer.public_key,
            block,
        )?;

        // ZIP-9: Sink gas to zero account
        let fork = state.forks.get(block.header.number).clone();
        let gas_fee_amount = if fork.transfer_gas_fee_to_zero_account {
            cumulative_gas_fee
        } else {
            block.gas_used().0 as u128
        };

        state.mutate_account(Address::ZERO, |a| {
            a.balance = a
                .balance
                .checked_add(gas_fee_amount)
                .ok_or(anyhow!("Overflow occurred in zero account balance"))?;
            Ok(())
        })?;

        if !fork.fund_accounts_from_zero_account.is_empty()
            && let Some(fork_height) = self
                .state
                .forks
                .find_height_fork_first_activated(ForkName::FundAccountsFromZeroAccount)
            && fork_height == block.header.number
        {
            for address_amount_pair in fork.fund_accounts_from_zero_account.clone() {
                state.mutate_account(Address::ZERO, |a| {
                    a.balance = a
                        .balance
                        .checked_sub(*address_amount_pair.1)
                        .ok_or(anyhow!("Underflow occurred in zero account balance"))?;
                    Ok(())
                })?;
                state.mutate_account(address_amount_pair.0, |a| {
                    a.balance = a
                        .balance
                        .checked_add(*address_amount_pair.1)
                        .ok_or(anyhow!("Overflow occurred in Faucet account balance"))?;
                    Ok(())
                })?;
            }
        };

        if fork.restore_xsgd_contract
            && let Some(fork_height) = self
                .state
                .forks
                .find_height_fork_first_activated(ForkName::RestoreXsgdContract)
            && fork_height == block.header.number
        {
            let code: Code = serde_json::from_slice(&hex::decode(XSGD_CODE)?)?;
            state.mutate_account(XSGD_MAINNET_ADDR, |a| {
                a.code = code;
                Ok(())
            })?;
        }
        if fork.revert_restore_xsgd_contract
            && let Some(fork_height) = self
                .state
                .forks
                .find_height_fork_first_activated(ForkName::RevertRestoreXsgdContract)
            && fork_height == block.header.number
        {
            state.mutate_account(XSGD_MAINNET_ADDR, |a| {
                a.code = Code::Evm(vec![]);
                Ok(())
            })?;
        }
        if fork.restore_ignite_wallet_contracts
            && let Some(fork_height) = self
                .state
                .forks
                .find_height_fork_first_activated(ForkName::RestoreIgniteWalletContracts)
            && fork_height == block.header.number
        {
            for (addr, code) in build_ignite_wallet_addr_scilla_code_map()?.iter() {
                state.mutate_account(*addr, |a| {
                    a.code = code.clone();
                    Ok(())
                })?;
            }
        }

        if self.block_is_first_in_epoch(block.header.number) {
            // Update state with any contract upgrades for this block
            state.contract_upgrade_apply_state_change(&self.config.consensus, block.header)?;
        }

        Ok(())
    }

    fn broadcast_commit_receipts(
        &self,
        from: Option<PeerId>,
        block: &Block,
        mut block_receipts: Vec<(TransactionReceipt, usize)>,
    ) -> Result<()> {
        // Broadcast receipts
        for (receipt, tx_index) in &mut block_receipts {
            receipt.block_hash = block.hash();
            // Avoid cloning the receipt if there are no subscriptions to send it to.
            if self.new_receipts.receiver_count() != 0 {
                let _ = self.new_receipts.send((receipt.clone(), *tx_index));
            }
        }

        // Important - only add blocks we are going to execute because they can potentially
        // overwrite the mapping of block height to block, which there should only be one of.
        // for example, this HAS to be after the deal with fork call
        if !self.db.contains_block(&block.hash())? {
            // Only tell the block store where this block came from if it wasn't from ourselves.
            let from = from.filter(|peer_id| *peer_id != self.peer_id());
            // If we were the proposer we would've already processed the block, hence the check
            self.add_block(from, block.clone())?;
        }
        {
            // helper scope to shadow db, to avoid moving it into the closure
            // closure has to be move to take ownership of block_receipts
            let db = &self.db;
            self.db.with_sqlite_tx(move |sqlite_tx| {
                for (receipt, _) in block_receipts {
                    db.insert_transaction_receipt_with_db_tx(sqlite_tx, receipt)?;
                }
                Ok(())
            })?;
        }

        self.db.mark_block_as_canonical(block.hash())?;

        Ok(())
    }

    fn create_txn_receipt(
        apply_result: TransactionApplyResult,
        tx_hash: Hash,
        tx_index: usize,
        cumulative_gas_used: EvmGas,
    ) -> TransactionReceipt {
        let success = apply_result.success();
        let contract_address = apply_result.contract_address();
        let gas_used = apply_result.gas_used();
        let accepted = apply_result.accepted();
        let (logs, transitions, errors, exceptions) = apply_result.into_parts();

        TransactionReceipt {
            tx_hash,
            block_hash: Hash::ZERO,
            index: tx_index as u64,
            success,
            contract_address,
            logs,
            transitions,
            gas_used,
            cumulative_gas_used,
            accepted,
            errors,
            exceptions,
        }
    }

    pub fn get_num_transactions(&self) -> Result<usize> {
        let count = self.db.get_total_transaction_count()?;
        Ok(count)
    }

    pub fn get_block_range(&self) -> Result<RangeInclusive<u64>> {
        let range = self.db.available_range()?;
        Ok(range)
    }

    pub fn get_sync_data(&self, db: Arc<Db>) -> Result<Option<SyncingStruct>> {
        self.sync.get_sync_data(db)
    }

    /// This function is intended for use only by admin_forceView API. It is dangerous and should not be touched outside of testing or test network recovery.
    ///
    /// Force set our view and override exponential timeout such that view timeouts at given timestamp
    /// View value must be larger than current
    pub fn force_view(&mut self, view: u64, timeout_at: String) -> Result<()> {
        if self.get_view()? > view {
            return Err(anyhow!(
                "view cannot be forced into lower view than current"
            ));
        }
        match timeout_at.parse::<DateTime>() {
            Ok(datetime) => self.force_view = Some((view, datetime)),
            Err(_) => {
                return Err(anyhow!(
                    "timeout date must be in format 2001-01-02T12:13:14Z"
                ));
            }
        };
        self.set_view(view, false)?;

        // Build a new view - We assume the network is stuck.
        if !self.db.get_voted_in_view()? {
            self.build_new_view()?;
        }
        Ok(())
    }

    fn in_committee(&mut self, val: bool) -> Result<()> {
        if val && !self.in_committee {
            self.in_committee = true;
            self.message_sender.send_message_to_coordinator(
                InternalMessage::SubscribeToGossipSubTopic(GossipSubTopic::Validator(
                    self.config.eth_chain_id,
                )),
            )?;
        }
        if !val && self.in_committee {
            self.in_committee = false;
            self.message_sender.send_message_to_coordinator(
                InternalMessage::UnsubscribeFromGossipSubTopic(GossipSubTopic::Validator(
                    self.config.eth_chain_id,
                )),
            )?;
        }
        Ok(())
    }

    pub fn clear_mempool(&self) {
        self.transaction_pool.write().clear();
    }

    /// Migrate the state of one block - writing new state to RocksDB; returns true if done.
    pub fn migrate_state_trie(&mut self) -> Result<bool> {
        let state_trie = self.db.state_trie()?;
        let mut migrate_at = state_trie.get_migrate_at()?;
        if migrate_at == u64::MAX {
            return Ok(true); // done
        }

        // replay one block - writing new state to RocksDB.
        let Some(parent_hash) = state_trie.get_root_hash(migrate_at.saturating_sub(1))? else {
            unimplemented!("parent state must exist!");
        };

        let brt = self
            .db
            .get_block_and_receipts_and_transactions(BlockFilter::Height(migrate_at))?
            .expect("block must exist");
        let block_hash = brt.block.state_root_hash();

        let brt_view = brt.block.view();
        // the history kept in memory is missing due to a node restart, load it from the database
        if self.state.ckpt_view_history.is_none() {
            let missed_views = self
                .db
                .read_ckpt_view_history()
                .unwrap()
                .iter()
                .map(|(view, pubkey)| (*view, NodePublicKey::from_bytes(pubkey).unwrap()))
                .collect::<std::collections::VecDeque<(u64, NodePublicKey)>>();
            let ckpt_view_history = crate::precompiles::ViewHistory {
                min_view: self.db.get_min_view_of_ckpt_view_history().unwrap(),
                missed_views,
            };
            self.state.ckpt_view_history = Some(Arc::new(RwLock::new(ckpt_view_history)));
        }
        let ckpt_min_view = self
            .state
            .ckpt_view_history
            .as_ref()
            .unwrap()
            .read()
            .min_view;
        self.state.ckpt_finalized_view = Some(brt_view);
        if ckpt_min_view > 1
            && brt_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW) < ckpt_min_view + MISSED_VIEW_WINDOW
        {
            error!(
                ?brt_view,
                ckpt_min_view,
                ckpt_finalized = brt_view,
                "~~~~~~~~~~> missed view history not available during state-sync"
            );
            return Err(anyhow!(
                "Missed view history not available during state-sync"
            ));
        }

        let cutover_at = state_trie.get_cutover_at()?;
        tracing::info!(end=%cutover_at,number=%migrate_at,state=%block_hash, "State-sync");
        self.replay_proposal(
            brt.block,
            brt.transactions.into_iter().map(|t| t.tx).collect_vec(),
            parent_hash,
        )?;

        // fast-forward to next block, skipping empty blocks, up to cutover threshold
        let mut parent_view = brt_view;
        while migrate_at < cutover_at {
            migrate_at = migrate_at.saturating_add(1); // check next block
            // add the views missed since the last replayed block to the history imported from a checkpoint
            let block = self
                .get_canonical_block_by_number(migrate_at)?
                .expect("Next block missing");
            let state_at = self.state.at_root(block_hash.into());
            let header = BlockHeader {
                view: parent_view,
                number: migrate_at - 1,
                ..Default::default()
            };
            let mut history = VecDeque::new();
            for view in parent_view + 1..block.view() {
                if let Ok(leader) = state_at.leader(view, header)
                    && view != parent_view + 1
                {
                    history.push_back((view, leader));
                    self.state
                        .ckpt_view_history
                        .as_ref()
                        .expect("Checkpoint view history missing")
                        .write()
                        .append_history(&mut history)?;
                    self.db.extend_ckpt_view_history(view, leader.as_bytes())?;
                    // TODO(jailing): collect them in a vector and call append_history only once
                }
            }
            self.state.ckpt_finalized_view = Some(block.view());
            parent_view = block.view();
            let Some(hash) = state_trie.get_root_hash(migrate_at)? else {
                tracing::warn!(number=%migrate_at,"State-sync retrying");
                return Ok(true); // retry later
            };
            if hash != block_hash {
                state_trie.set_migrate_at(migrate_at)?;
                return Ok(false);
            }
        }
        // done
        tracing::info!("State-sync complete!");
        state_trie.finish_migration()?;
        self.merge_missed_view_history()?;
        Ok(true)
    }

    pub fn merge_missed_view_history(&mut self) -> Result<()> {
        // state sync finished at ckpt_finalized_view which is equal
        // or greater than the cutover block's view, so the state
        // required to determine the leader is always available
        let mut view = self
            .state
            .ckpt_finalized_view
            .expect("Checkpoint finalized view missing");
        // we continue extending the checkpoint's missed views until
        // we reach the beginning of the node's missed view history
        loop {
            // find the next missed view
            while self.get_block_by_view(view)?.is_some()
                && self.state.view_history.read().min_view > view
            {
                view += 1;
            }
            if self.state.view_history.read().min_view <= view {
                break;
            }
            // the parent view was the one before we found a missed view in the loop above
            let block = self
                .get_block_by_view(view.saturating_sub(1))?
                .expect("Parent block missing");
            let state_at = self.state.at_root(block.hash().into());
            let header = BlockHeader {
                view: block.view(),
                number: block.number(),
                ..Default::default()
            };
            // skip the first missed view in a row as its block must have been reorged
            view += 1;
            // but add all subsequent missed views to the history
            let mut history = VecDeque::new();
            while self.get_block_by_view(view)?.is_none()
                && self.state.view_history.read().min_view > view
            {
                if let Ok(leader) = state_at.leader(view, header) {
                    history.push_back((view, leader));
                    self.state
                        .ckpt_view_history
                        .as_ref()
                        .expect("Checkpoint view history missing")
                        .write()
                        .append_history(&mut history)?;
                    self.db.extend_ckpt_view_history(view, leader.as_bytes())?;
                    // TODO(jailing): collect them in a vector and call append_history only once
                }
                view += 1;
            }
        }
        info!(
            view_history = %*self.state.view_history.read(),
            last_ckpt_view = view, "History imported from the checkpoint can be merged"
        );
        // Clone the checkpoint history to avoid borrow conflict with merge_history
        let mut ckpt_history = self
            .state
            .ckpt_view_history
            .as_ref()
            .expect("Checkpoint view history missing")
            .read()
            .clone();
        merge_history(self, &mut ckpt_history, view)?;
        self.state.ckpt_view_history = None;
        self.state.ckpt_finalized_view = None;
        self.db.reset_ckpt_view_history()?;
        Ok(())
    }
}
