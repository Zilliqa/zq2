use std::{
    cell::RefCell, collections::BTreeMap, error::Error, fmt::Display, sync::Arc, time::Duration,
};

use alloy::primitives::{Address, U256};
use anyhow::{anyhow, Context, Result};
use bitvec::{bitarr, order::Msb0};
use eth_trie::{EthTrie, MemoryDB, Trie};
use itertools::Itertools;
use libp2p::PeerId;
use revm::Inspector;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tracing::*;

use crate::{
    block_store::BlockStore,
    blockhooks,
    cfg::{ConsensusConfig, NodeConfig},
    crypto::{verify_messages, Hash, NodePublicKey, NodeSignature, SecretKey},
    db::{self, Db},
    exec::{PendingState, TransactionApplyResult},
    inspector::{self, ScillaInspector, TouchedAddressInspector},
    message::{
        AggregateQc, BitArray, BitSlice, Block, BlockHeader, BlockRef, BlockStrategy,
        ExternalMessage, InternalMessage, NewView, ProcessProposal, Proposal, QuorumCertificate,
        Vote, MAX_COMMITTEE_SIZE,
    },
    node::{MessageSender, NetworkMessage, OutgoingMessageFailure},
    pool::{TransactionPool, TxAddResult, TxPoolContent},
    state::State,
    time::SystemTime,
    transaction::{EvmGas, SignedTransaction, TransactionReceipt, VerifiedTransaction},
};

#[derive(Debug)]
struct NewViewVote {
    signatures: Vec<NodeSignature>,
    cosigned: BitArray,
    cosigned_weight: u128,
    qcs: Vec<QuorumCertificate>,
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

type BlockVotes = (Vec<NodeSignature>, BitArray, u128, bool);

#[derive(Debug)]
struct CachedLeader {
    block_number: u64,
    view: u64,
    next_leader: Validator,
}

type EarlyProposal = (
    Block,
    Vec<VerifiedTransaction>,
    EthTrie<MemoryDB>,
    EthTrie<MemoryDB>,
);

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
///    which guarantees all nodes eventually are on the same view
/// - Nodes send a NewView message, which is a signature over the view, and their highQC
/// - This is collected to form an aggQC
/// - This aggQC is used to propose a block
/// - The votes on that block form the next highQC
///
#[derive(Debug)]
pub struct Consensus {
    secret_key: SecretKey,
    config: NodeConfig,
    message_sender: MessageSender,
    reset_timeout: UnboundedSender<Duration>,
    pub block_store: BlockStore,
    latest_leader_cache: RefCell<Option<CachedLeader>>,
    votes: BTreeMap<Hash, BlockVotes>,
    /// Votes for a block we don't have stored. They are retained in case we receive the block later.
    // TODO(#719): Consider how to limit the size of this.
    buffered_votes: BTreeMap<Hash, Vec<Vote>>,
    new_views: BTreeMap<u64, NewViewVote>,
    pub high_qc: QuorumCertificate,
    view: View,
    finalized_view: u64,
    /// The account store.
    state: State,
    /// The persistence database
    db: Arc<Db>,
    /// Actions that act on newly created blocks
    transaction_pool: TransactionPool,
    /// Pending proposal. Gets created as soon as we become aware that we are leader for this view.
    early_proposal: Option<EarlyProposal>,
    /// Flag indicating that block creation should be postponed at least until empty_block_timeout is reached
    create_next_block_on_timeout: bool,
    pub new_blocks: broadcast::Sender<BlockHeader>,
    pub receipts: broadcast::Sender<(TransactionReceipt, usize)>,
    pub new_transactions: broadcast::Sender<VerifiedTransaction>,
    pub new_transaction_hashes: broadcast::Sender<Hash>,
}

// View in consensus should be have access monitored so last_timeout is always correct
#[derive(Debug)]
struct View {
    view: u64,
    last_timeout: SystemTime,
}

impl View {
    pub fn new(view: u64) -> Self {
        View {
            view,
            last_timeout: SystemTime::now(),
        }
    }

    pub fn get_view(&self) -> u64 {
        self.view
    }

    pub fn set_view(&mut self, view: u64) {
        match view.cmp(&self.view) {
            std::cmp::Ordering::Less => {
                warn!(
                    "Tried to set view {} to lower view {} - this is incorrect",
                    self.view, view
                );
            }
            std::cmp::Ordering::Equal => {
                trace!("Tried to set view to same view - this is incorrect");
            }
            std::cmp::Ordering::Greater => {
                self.view = view;
                self.last_timeout = SystemTime::now();
            }
        }
    }

    pub fn last_timeout(&self) -> SystemTime {
        self.last_timeout
    }
}

impl Consensus {
    pub fn new(
        secret_key: SecretKey,
        config: NodeConfig,
        message_sender: MessageSender,
        reset_timeout: UnboundedSender<Duration>,
        db: Arc<Db>,
    ) -> Result<Self> {
        trace!(
            "Opening database in {:?} for shard {}",
            config.data_dir,
            config.eth_chain_id
        );

        let block_store = BlockStore::new(&config, db.clone(), message_sender.clone())?;

        // Start chain from checkpoint. Load data file and initialise data in tables
        let mut checkpoint_data = None;
        if let Some(checkpoint) = &config.load_checkpoint {
            trace!("Loading state from checkpoint: {:?}", checkpoint);
            checkpoint_data = db.load_trusted_checkpoint(
                &checkpoint.file,
                &checkpoint.hash,
                config.eth_chain_id,
            )?;
        }

        let latest_block = db
            .get_latest_finalized_view()?
            .map(|view| {
                block_store
                    .get_block_by_view(view)?
                    .ok_or_else(|| anyhow!("no header found at view {view}"))
            })
            .transpose()?;

        let mut state = if let Some(latest_block) = &latest_block {
            trace!("Loading state from latest block");
            State::new_at_root(
                db.state_trie()?,
                latest_block.state_root_hash().into(),
                config.clone(),
                block_store.clone_read_only(),
            )
        } else {
            trace!("Contructing new state from genesis");
            State::new_with_genesis(
                db.state_trie()?,
                config.clone(),
                block_store.clone_read_only(),
            )?
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
                    let high_block = block_store
                        .get_block(qc.block_hash)?
                        .ok_or_else(|| anyhow!("missing block that high QC points to!"))?;

                    let finalized_number = db
                        .get_latest_finalized_view()?
                        .ok_or_else(|| anyhow!("missing latest finalized view!"))?;
                    let finalized_block = db
                        .get_block_by_view(finalized_number)?
                        .ok_or_else(|| anyhow!("missing finalized block!"))?;

                    let start_view = std::cmp::max(high_block.view(), finalized_block.view()) + 1;
                    trace!(
                        "recovery: high_block view {0}, finalized_number {1} , start_view {2}",
                        high_block.view(),
                        finalized_number,
                        start_view
                    );

                    if finalized_number > high_block.view() {
                        // We know of a finalized view higher than the view in finalized_number; start there.
                        state.set_to_root(finalized_block.header.state_root_hash.into());
                    } else {
                        // The high_block contains the latest finalized view. Start there.
                        state.set_to_root(high_block.header.state_root_hash.into());
                    }

                    // If we have newer blocks, erase them
                    // @todo .. more elegantly :-)
                    loop {
                        let highest_block_number = db
                            .get_highest_canonical_block_number()?
                            .ok_or_else(|| anyhow!("can't find highest block num in database!"))?;

                        let head_block = block_store
                            .get_canonical_block_by_number(highest_block_number)?
                            .ok_or_else(|| anyhow!("missing head block!"))?;
                        trace!(
                            "recovery: highest_block_number {highest_block_number} view {0}",
                            head_block.view()
                        );

                        if head_block.view() > high_block.view()
                            && head_block.view() > finalized_number
                        {
                            trace!("recovery: stored block {0} reverted", highest_block_number);
                            db.remove_transactions_executed_in_block(&head_block.hash())?;
                            db.remove_block(&head_block)?;
                        } else {
                            break;
                        }
                    }

                    info!("During recovery, starting consensus at view {}", start_view);
                    (start_view, qc)
                }
                None => {
                    let start_view = 1;
                    (start_view, QuorumCertificate::genesis())
                }
            }
        };

        let mut consensus = Consensus {
            secret_key,
            config,
            block_store,
            latest_leader_cache: RefCell::new(None),
            message_sender,
            reset_timeout,
            votes: BTreeMap::new(),
            buffered_votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            high_qc,
            view: View::new(start_view),
            finalized_view: start_view.saturating_sub(1),
            state,
            db,
            transaction_pool: Default::default(),
            early_proposal: None,
            create_next_block_on_timeout: false,
            new_blocks: broadcast::Sender::new(4),
            receipts: broadcast::Sender::new(128),
            new_transactions: broadcast::Sender::new(128),
            new_transaction_hashes: broadcast::Sender::new(128),
        };

        // If we're at genesis, add the genesis block.
        if latest_block_view == 0 {
            if let Some(genesis) = latest_block {
                // The genesis block might already be stored and we were interrupted before we got a
                // QC for it.
                if consensus.get_block(&genesis.hash())?.is_none() {
                    consensus.add_block(None, genesis.clone())?;
                }
            }
            // treat genesis as finalized
            consensus.finalize_view(latest_block_view)?;
        }

        // If we started from a checkpoint, execute the checkpointed block now
        if let Some((block, transactions, _parent)) = checkpoint_data {
            consensus.execute_block(None, &block, transactions, &consensus.state.get_stakers()?)?;
        }

        Ok(consensus)
    }

    pub fn public_key(&self) -> NodePublicKey {
        self.secret_key.node_public_key()
    }

    pub fn head_block(&self) -> Block {
        let highest_block_number = self
            .block_store
            .get_highest_canonical_block_number()
            .unwrap()
            .unwrap();
        self.block_store
            .get_canonical_block_by_number(highest_block_number)
            .unwrap()
            .unwrap()
    }

    pub fn timeout(&mut self) -> Result<Option<NetworkMessage>> {
        // We never want to timeout while on view 1
        if self.view.get_view() == 1 {
            let block = self
                .get_block_by_view(0)
                .unwrap()
                .ok_or_else(|| anyhow!("missing block"))?;
            // If we're in the genesis committee, vote again.
            let stakers = self.state.get_stakers()?;
            if stakers.iter().any(|v| *v == self.public_key()) {
                info!("timeout in view: {:?}, we will vote for block rather than incrementing view, block hash: {}", self.view.get_view(), block.hash());
                let leader = self.leader_at_block(&block, self.view.get_view()).unwrap();
                let vote = self.vote_from_block(&block);
                return Ok(Some((
                    Some(leader.peer_id),
                    ExternalMessage::Vote(Box::new(vote)),
                )));
            } else {
                info!(
                    "We are on view: {:?} but we are not a validator, so we are waiting.",
                    self.view.get_view()
                );
            }

            return Ok(None);
        }

        let (
            time_since_last_view_change,
            exponential_backoff_timeout,
            minimum_time_left_for_empty_block,
        ) = self.get_consensus_timeout_params();

        trace!(
            "timeout reached create_next_block_on_timeout: {}",
            self.create_next_block_on_timeout
        );
        if self.create_next_block_on_timeout {
            let empty_block_timeout_ms =
                self.config.consensus.empty_block_timeout.as_millis() as u64;

            let has_txns_for_next_block = self.transaction_pool.has_txn_ready();

            // Check if enough time elapsed or there's something in mempool or we don't have enough
            // time but let's try at least until new view can happen
            if time_since_last_view_change > empty_block_timeout_ms
                || has_txns_for_next_block
                || (time_since_last_view_change + minimum_time_left_for_empty_block
                    >= exponential_backoff_timeout)
            {
                if let Ok(Some((block, transactions))) = self.propose_new_block() {
                    self.create_next_block_on_timeout = false;
                    return Ok(Some((
                        None,
                        ExternalMessage::Proposal(Proposal::from_parts(block, transactions)),
                    )));
                };
            } else {
                self.reset_timeout.send(Duration::from_millis(
                    empty_block_timeout_ms - time_since_last_view_change + 1,
                ))?;
                return Ok(None);
            }
        }

        // Now consider whether we want to timeout - the timeout duration doubles every time, so it
        // Should eventually have all nodes on the same view

        if time_since_last_view_change < exponential_backoff_timeout {
            trace!(
                "Not proceeding with view change. Current view: {} - time since last: {}, timeout requires: {}",
                self.view.get_view(),
                time_since_last_view_change,
                exponential_backoff_timeout
            );
            return Ok(None);
        }

        trace!("Considering view change: view: {} time since: {} timeout: {} last known view: {} last hash: {}", self.view.get_view(), time_since_last_view_change, exponential_backoff_timeout, self.high_qc.view, self.head_block().hash());

        let block = self.get_block(&self.high_qc.block_hash)?.ok_or_else(|| {
            anyhow!("missing block corresponding to our high qc - this should never happen")
        })?;

        let stakers = self.state.get_stakers_at_block(&block)?;
        if !stakers.iter().any(|v| *v == self.public_key()) {
            debug!(
                "can't vote for new view, we aren't in the committee of length {:?}",
                stakers.len()
            );
            return Ok(None);
        }

        let view_difference = self.view.get_view().saturating_sub(self.high_qc.view);
        let consensus_timeout_ms = self.config.consensus.consensus_timeout.as_millis() as u64;
        let next_exponential_backoff_timeout =
            consensus_timeout_ms * 2u64.pow(((view_difference + 1) as u32).saturating_sub(2));
        info!(
            "***** TIMEOUT: View is now {} -> {}. Next view change in {}ms",
            self.view.get_view(),
            self.view.get_view() + 1,
            next_exponential_backoff_timeout
        );

        self.view.set_view(self.view.get_view() + 1);
        let Some(leader) = self.leader_at_block(&block, self.view.get_view()) else {
            return Ok(None);
        };

        let new_view = NewView::new(
            self.secret_key,
            self.high_qc,
            self.view.get_view(),
            self.secret_key.node_public_key(),
        );

        Ok(Some((
            Some(leader.peer_id),
            ExternalMessage::NewView(Box::new(new_view)),
        )))
    }

    fn get_consensus_timeout_params(&self) -> (u64, u64, u64) {
        let consensus_timeout_ms = self.config.consensus.consensus_timeout.as_millis() as u64;
        let time_since_last_view_change = SystemTime::now()
            .duration_since(self.view.last_timeout())
            .unwrap_or_default()
            .as_millis() as u64;
        let view_difference = self.view.get_view().saturating_sub(self.high_qc.view);
        // in view N our highQC is the one we obtained in view N-1 (or before) and its view is N-2 (or lower)
        // in other words, the current view is always at least 2 views ahead of the highQC's view
        // i.e. to get `consensus_timeout_ms * 2^0` we have to subtract 2 from `view_difference`
        let exponential_backoff_timeout =
            consensus_timeout_ms * 2u64.pow((view_difference as u32).saturating_sub(2));

        let minimum_time_left_for_empty_block = self
            .config
            .consensus
            .minimum_time_left_for_empty_block
            .as_millis() as u64;

        trace!(
            time_since_last_view_change,
            exponential_backoff_timeout,
            minimum_time_left_for_empty_block,
        );

        (
            time_since_last_view_change,
            exponential_backoff_timeout,
            minimum_time_left_for_empty_block,
        )
    }

    pub fn peer_id(&self) -> PeerId {
        self.secret_key.to_libp2p_keypair().public().to_peer_id()
    }

    pub fn proposal(
        &mut self,
        from: PeerId,
        proposal: Proposal,
        during_sync: bool,
    ) -> Result<Option<NetworkMessage>> {
        self.cleanup_votes();
        let (block, transactions) = proposal.into_parts();
        let head_block = self.head_block();

        trace!(
            block_view = block.view(),
            block_number = block.number(),
            "handling block proposal {}",
            block.hash()
        );

        if self.block_store.contains_block(&block.hash())? {
            trace!("ignoring block proposal, block store contains this block already");
            return Ok(None);
        }

        if block.view() <= head_block.header.view {
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

        match self.check_block(&block, during_sync) {
            Ok(()) => {}
            Err((e, temporary)) => {
                // If this block could become valid in the future, buffer it.
                if temporary {
                    self.block_store.buffer_proposal(
                        from,
                        Proposal::from_parts_with_hashes(
                            block,
                            transactions
                                .into_iter()
                                .map(|tx| {
                                    let hash = tx.calculate_hash();
                                    (tx, hash)
                                })
                                .collect(),
                        ),
                    )?;
                } else {
                    warn!(?e, "invalid block proposal received!");
                }
                return Ok(None);
            }
        }

        self.update_high_qc_and_view(block.agg.is_some(), block.header.qc)?;

        let proposal_view = block.view();
        let parent = self
            .get_block(&block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block parent"))?;

        trace!("checking if block view {} is safe", block.view());

        // If the proposed block is safe, vote for it and advance to the next round.
        if self.check_safe_block(&block, during_sync)? {
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
                warn!("state root hash prior to block execution mismatch, expected: {:?}, actual: {:?}, head: {:?}", parent.state_root_hash(), self.state.root_hash()?, head_block);
                self.state.set_to_root(parent.state_root_hash().into());
            }
            let stakers: Vec<_> = self.state.get_stakers()?;

            // Only tell the block store where this block came from if it wasn't from ourselves.
            let from = (self.peer_id() != from).then_some(from);
            self.execute_block(from, &block, transactions, &stakers)?;

            if self.view.get_view() != proposal_view + 1 {
                self.view.set_view(proposal_view + 1);

                debug!(
                    "*** setting view to proposal view... view is now {}",
                    self.view.get_view()
                );
            }

            if let Some(buffered_votes) = self.buffered_votes.remove(&block.hash()) {
                // If we've buffered votes for this block, process them now.
                let count = buffered_votes.len();
                for (i, vote) in buffered_votes.into_iter().enumerate() {
                    trace!("applying buffered vote {} of {count}", i + 1);
                    if let Some((block, transactions)) = self.vote(vote)? {
                        // If we reached the supermajority while processing this vote, send the next block proposal.
                        // Further votes are ignored (including our own).
                        // TODO(#720): We should prioritise our own vote.
                        trace!("supermajority reached, sending next proposal");
                        return Ok(Some((
                            None,
                            ExternalMessage::Proposal(Proposal::from_parts(block, transactions)),
                        )));
                    }
                }

                // If we reach this point, we had some buffered votes but they were not sufficient to reach a
                // supermajority.
            }

            // Get possibly updated list of stakers
            let stakers = self.state.get_stakers()?;

            if !stakers.iter().any(|v| *v == self.public_key()) {
                debug!(
                    "can't vote for block proposal, we aren't in the committee of length {:?}",
                    stakers.len()
                );
                return Ok(None);
            } else {
                let vote = self.vote_from_block(&block);
                let next_leader = self.leader_at_block(&block, self.view.get_view());
                self.create_next_block_on_timeout = false;
                self.early_proposal = None;

                let Some(next_leader) = next_leader else {
                    warn!("Next leader is currently not reachable, has it joined committee yet?");
                    return Ok(None);
                };

                self.latest_leader_cache.replace(Some(CachedLeader {
                    block_number: block.number(),
                    view: self.view.get_view(),
                    next_leader,
                }));

                if !during_sync {
                    trace!(proposal_view, ?next_leader, "voting for block");
                    return Ok(Some((
                        Some(next_leader.peer_id),
                        ExternalMessage::Vote(Box::new(vote)),
                    )));
                }
            }
        } else {
            trace!("block is not safe");
        }

        Ok(None)
    }

    /// Apply the rewards at the tail-end of the Proposal.
    /// Note that the algorithm below is mentioned in cfg.rs - if you change the way
    /// rewards are calculated, please change the comments in the configuration structure there.
    fn apply_rewards_late_at(
        parent_state_hash: Hash,
        at_state: &mut State,
        config: &ConsensusConfig,
        committee: &[NodePublicKey],
        proposer: NodePublicKey,
        view: u64,
        cosigned: &BitSlice,
    ) -> Result<()> {
        debug!("apply late rewards in view {view}");
        let rewards_per_block: u128 = *config.rewards_per_hour / config.blocks_per_hour as u128;

        // Get the reward addresses from the parent state
        let parent_state = at_state.at_root(parent_state_hash.into());

        let proposer_address = parent_state.get_reward_address(proposer)?;

        let mut total_cosigner_stake = 0;
        let cosigner_stake: Vec<_> = committee
            .iter()
            .enumerate()
            .filter(|(i, _)| cosigned[*i])
            .map(|(_, pub_key)| {
                let reward_address = parent_state.get_reward_address(*pub_key).unwrap();
                let stake = parent_state.get_stake(*pub_key).unwrap().unwrap().get();
                total_cosigner_stake += stake;
                (reward_address, stake)
            })
            .collect();

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

    pub fn apply_transaction<I: Inspector<PendingState> + ScillaInspector>(
        &mut self,
        txn: VerifiedTransaction,
        current_block: BlockHeader,
        inspector: I,
    ) -> Result<Option<TransactionApplyResult>> {
        let db = self.db.clone();
        let state = &mut self.state;
        Self::apply_transaction_at(state, db, txn, current_block, inspector)
    }

    pub fn apply_transaction_at<I: Inspector<PendingState> + ScillaInspector>(
        state: &mut State,
        db: Arc<Db>,
        txn: VerifiedTransaction,
        current_block: BlockHeader,
        inspector: I,
    ) -> Result<Option<TransactionApplyResult>> {
        let hash = txn.hash;

        if !db.contains_transaction(&txn.hash)? {
            db.insert_transaction(&txn.hash, &txn.tx)?;
        }

        let result = state.apply_transaction(txn.clone(), current_block, inspector);
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

    pub fn get_txns_to_execute(&mut self) -> Vec<VerifiedTransaction> {
        let mut gas_left = self.config.consensus.eth_block_gas_limit;
        std::iter::from_fn(|| self.transaction_pool.best_transaction())
            .filter(|txn| {
                let account_nonce = self.state.must_get_account(txn.signer).nonce;
                // Ignore this transaction if it is no longer valid.
                // Transactions are (or will be) valid iff their nonce is greater than the account
                // nonce OR if they have no nonce
                txn.tx
                    .nonce()
                    .map(|tx_nonce| tx_nonce >= account_nonce)
                    .unwrap_or(true)
            })
            .take_while(|txn| {
                if let Some(g) = gas_left.checked_sub(txn.tx.gas_limit()) {
                    gas_left = g;
                    true
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn txpool_content(&self) -> TxPoolContent {
        let mut content = self.transaction_pool.preview_content();
        // Ignore txns having too low nonces
        content.pending.retain(|txn| {
            let account_nonce = self.state.must_get_account(txn.signer).nonce;
            txn.tx.nonce().unwrap() >= account_nonce
        });

        content.queued.retain(|txn| {
            let account_nonce = self.state.must_get_account(txn.signer).nonce;
            txn.tx.nonce().unwrap() >= account_nonce
        });
        content
    }

    pub fn pending_transaction_count(&self, account: Address) -> u64 {
        let current_nonce = self.state.must_get_account(account).nonce;

        self.transaction_pool
            .pending_transaction_count(account, current_nonce)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.db.get_touched_transactions(address)
    }

    /// Clear up anything in memory that is no longer required. This is to avoid memory leaks.
    pub fn cleanup_votes(&mut self) {
        // Wrt votes, we only care about votes on hashes for the current view or higher
        let keys_to_process: Vec<_> = self.votes.keys().copied().collect();

        for key in keys_to_process {
            if let Ok(Some(block)) = self.get_block(&key) {
                // Remove votes for blocks that have been finalized. However, note that the block hashes which are keys
                // into `self.votes` are the parent hash of the (potential) block that is being voted on. Therefore, we
                // subtract one in this condition to ensure there is no chance of removing votes for blocks that still
                // have a chance of being mined. It is possible this is unnecessary, since `self.finalized_view` is
                // already at least 2 views behind the head of the chain, but keeping one extra vote in memory doesn't
                // cost much and does make us more confident that we won't dispose of valid votes.
                if block.view() < self.finalized_view.saturating_sub(1) {
                    trace!(block_view = %block.view(), block_hash = %key, "cleaning vote");
                    self.votes.remove(&key);
                }
            } else {
                warn!("Missing block for vote (this shouldn't happen), removing from memory");
                trace!(block_hash = %key, "cleaning vote");
                self.votes.remove(&key);
            }
        }

        // Wrt new views, we only care about new views for the current view or higher
        self.new_views.retain(|k, _| *k >= self.view.get_view());
    }

    pub fn vote(&mut self, vote: Vote) -> Result<Option<(Block, Vec<VerifiedTransaction>)>> {
        let block_hash = vote.block_hash;
        let block_view = vote.view;
        let current_view = self.view.get_view();
        trace!(block_view, current_view, %block_hash, "handling vote");

        // if the vote is too old and does not count anymore
        if block_view + 1 < self.view.get_view() {
            trace!("vote is too old");
            return Ok(None);
        }

        // Verify the signature in the vote matches the public key in the vote. This tells us that the vote was created
        // by the owner of `vote.public_key`, but we don't yet know that a vote from that node is valid. In other
        // words, a malicious node which is not part of the consensus committee may send us a vote and this check will
        // still pass. We later validate that the owner of `vote.public_key` is a valid voter.
        vote.verify()?;

        // Retrieve the actual block this vote is for.
        let Some(block) = self.get_block(&block_hash)? else {
            trace!("vote for unknown block, buffering");
            // If we don't have the block yet, we buffer the vote in case we recieve the block later. Note that we
            // don't know the leader of this view without the block, so we may be storing this unnecessarily, however
            // non-malicious nodes should only have sent us this vote if they thought we were the leader.
            self.buffered_votes
                .entry(block_hash)
                .or_default()
                .push(vote);
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
        let committee = self.state.get_stakers_at_block(&block)?;

        // verify the sender's signature on block_hash
        let Some((index, _)) = committee
            .iter()
            .enumerate()
            .find(|(_, &v)| v == vote.public_key)
        else {
            warn!("Skipping vote outside of committee");
            return Ok(None);
        };

        let (mut signatures, mut cosigned, mut cosigned_weight, mut supermajority_reached) =
            self.votes.get(&block_hash).cloned().unwrap_or_else(|| {
                (
                    Vec::new(),
                    bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE],
                    0,
                    false,
                )
            });

        if supermajority_reached {
            trace!(
                "(vote) supermajority already reached in this round {}",
                self.view.get_view()
            );
            return Ok(None);
        }

        // if the vote is new, store it
        if !cosigned[index] {
            signatures.push(vote.signature());
            cosigned.set(index, true);
            // Update state to root pointed by voted block (in meantime it might have changed!)
            self.state.set_to_root(block.state_root_hash().into());
            let Some(weight) = self.state.get_stake(vote.public_key)? else {
                return Err(anyhow!("vote from validator without stake"));
            };
            cosigned_weight += weight.get();

            let total_weight = self.total_weight(&committee);
            supermajority_reached = cosigned_weight * 3 > total_weight * 2;
            let current_view = self.view.get_view();
            trace!(
                cosigned_weight,
                supermajority_reached,
                total_weight,
                current_view,
                vote_view = block_view + 1,
                "storing vote"
            );
            self.votes.insert(
                block_hash,
                (
                    signatures.clone(),
                    cosigned,
                    cosigned_weight,
                    supermajority_reached,
                ),
            );
            // if we are already in the round in which the vote counts and have reached supermajority
            if supermajority_reached {
                // We propose new block immediately if there's something in mempool or it's the first view
                // Otherwise the block will be proposed on timeout
                if self.view.get_view() == 1 {
                    return self.propose_new_block();
                }

                self.early_proposal_assemble_at(None)?;

                return self.ready_for_block_proposal();
            }
        } else {
            self.votes.insert(
                block_hash,
                (signatures, cosigned, cosigned_weight, supermajority_reached),
            );
        }

        // Either way assemble early proposal now if it doesnt already exist
        self.early_proposal_assemble_at(None)?;

        Ok(None)
    }

    /// Finalise the early Proposal.
    /// This should only run after majority QC or aggQC are available.
    /// It applies the rewards and produces the final Proposal.
    fn early_proposal_finish_at(&mut self, proposal: Block) -> Result<Option<Block>> {
        // Retrieve parent block data
        let parent_block = self
            .get_block(&proposal.parent_hash())?
            .context("missing parent block")?;
        let parent_block_hash = parent_block.hash();

        let mut state = self.state.clone();
        let previous_state_root_hash = state.root_hash()?;
        state.set_to_root(proposal.state_root_hash().into());

        // Compute the majority QC. If aggQC exists then QC is already set to correct value.
        let (final_qc, committee) = match proposal.agg {
            Some(_) => {
                let committee: Vec<_> = self.committee_for_hash(proposal.header.qc.block_hash)?;
                (proposal.header.qc, committee)
            }
            None => {
                // Check for majority
                let Some((signatures, cosigned, _, supermajority_reached)) =
                    self.votes.get(&parent_block_hash)
                else {
                    warn!("tried to finalise a proposal without any votes");
                    return Ok(None);
                };
                if !supermajority_reached {
                    warn!("tried to finalise a proposal without majority");
                    return Ok(None);
                };
                // Retrieve the previous leader and committee - for rewards
                let committee = state.get_stakers_at_block(&parent_block)?;
                (
                    self.qc_from_bits(
                        parent_block_hash,
                        signatures,
                        *cosigned,
                        parent_block.view(),
                    ),
                    committee,
                )
            }
        };

        let proposer = self
            .leader_at_block(&parent_block, proposal.view())
            .context("missing parent block leader")?
            .public_key;
        // Apply the rewards when exiting the round
        Self::apply_rewards_late_at(
            parent_block.state_root_hash(),
            &mut state,
            &self.config.consensus,
            &committee,
            proposer, // Last leader
            proposal.view(),
            &final_qc.cosigned, // QC cosigners
        )?;

        // ZIP-9: Sink gas to zero account
        state.mutate_account(Address::ZERO, |a| {
            a.balance = a
                .balance
                .checked_add(proposal.gas_used().0 as u128)
                .ok_or(anyhow!("Overflow occured in zero account balance"))?;
            Ok(())
        })?;

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
            SystemTime::max(SystemTime::now(), parent_block.timestamp()),
            proposal.header.gas_used,
            proposal.header.gas_limit,
        );

        // Restore the state to previous
        state.set_to_root(previous_state_root_hash.into());
        self.state = state;

        // Return the final proposal
        Ok(Some(proposal))
    }

    /// Assembles the Proposal block early.
    /// This is performed before the majority QC is available.
    /// It does all the needed work but with a dummy QC.
    fn early_proposal_assemble_at(&mut self, agg: Option<AggregateQc>) -> Result<()> {
        if self.early_proposal.is_some()
            && self.early_proposal.as_ref().unwrap().0.view() == self.view()
        {
            return Ok(());
        }
        info!("assemble early proposal for view {}", self.view.get_view());

        let (qc, parent) = match agg {
            // Create dummy QC for now if aggQC not provided
            None => {
                // Start with highest canonical block
                let num = self
                    .db
                    .get_highest_canonical_block_number()?
                    .context("no canonical blocks")?; // get highest canonical block number
                let block = self
                    .get_canonical_block_by_number(num)?
                    .context("missing canonical block")?; // retrieve highest canonical block
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

        info!("parent block number: {}", parent.header.number);

        // Ensure sane state
        if self.state.root_hash()? != parent.state_root_hash() {
            warn!(
                "state root hash mismatch, expected: {:?}, actual: {:?}",
                parent.state_root_hash(),
                self.state.root_hash()?
            );
        }

        // Internal states
        let mut receipts_trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
        let mut transactions_trie: EthTrie<MemoryDB> =
            eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));
        let applied_txs = Vec::<VerifiedTransaction>::new();

        // This is a partial header of a block that will be proposed with some transactions executed below.
        // It is needed so that each transaction is executed within proper block context (the block it belongs to)
        let executed_block_header = BlockHeader {
            view: self.view(),
            number: parent.header.number + 1,
            timestamp: parent.header.timestamp, // will be overridden by `finish_early_proposal_at`
            gas_limit: self.config.consensus.eth_block_gas_limit,
            ..BlockHeader::default()
        };

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

        self.early_proposal = Some((proposal, applied_txs, transactions_trie, receipts_trie));
        self.early_proposal_apply_transactions()?;

        Ok(())
    }

    /// Updates self.early_proposal data (proposal, applied_transactions, transactions_trie, receipts_trie) to include any transactions in the mempool
    fn early_proposal_apply_transactions(&mut self) -> Result<()> {
        if self.early_proposal.is_none() {
            error!("could not apply transactions to early_proposal because it does not exist");
            return Ok(());
        }

        let mut state = self.state.clone();
        let previous_state_root_hash = state.root_hash()?;

        let proposal = self.early_proposal.as_ref().unwrap().0.clone();

        // Use state root hash of current early proposal
        state.set_to_root(proposal.state_root_hash().into());
        // Internal states
        let mut updated_root_hash: Hash = state.root_hash()?;
        let mut gas_left = proposal.header.gas_limit - proposal.header.gas_used;
        let mut tx_index_in_block = proposal.transactions.len();

        // Assemble new block with whatever is in the mempool
        while let Some(tx) = self.transaction_pool.best_transaction() {
            // First - check if we have time left to process txns and give enough time for block propagation
            let (
                time_since_last_view_change,
                exponential_backoff_timeout,
                minimum_time_left_for_empty_block,
            ) = self.get_consensus_timeout_params();

            if time_since_last_view_change + minimum_time_left_for_empty_block
                >= exponential_backoff_timeout
            {
                // don't have time, reinsert txn.
                self.transaction_pool.insert_ready_transaction(tx);
                break;
            }

            // Apply specific txn
            let result = Self::apply_transaction_at(
                &mut state,
                self.db.clone(),
                tx.clone(),
                proposal.header,
                inspector::noop(),
            )?;

            // Skip transactions whose execution resulted in an error and drop them.
            let Some(result) = result else {
                warn!("Dropping failed transaction: {:?}", tx.hash);
                continue;
            };

            // Decrement gas price and break loop if limit is exceeded
            gas_left = if let Some(g) = gas_left.checked_sub(result.gas_used()) {
                g
            } else {
                // undo last transaction
                info!(
                    nonce = tx.tx.nonce(),
                    "gas limit reached, returning last transaction to pool",
                );
                self.transaction_pool.insert_ready_transaction(tx);
                state.set_to_root(updated_root_hash.into());
                break;
            };

            // Do necessary work to assemble the transaction
            self.transaction_pool.mark_executed(&tx);

            // Grab and update early_proposal data in own scope to avoid multiple mutable references to self
            {
                let (_, applied_txs, transactions_trie, receipts_trie) =
                    self.early_proposal.as_mut().unwrap();

                transactions_trie.insert(tx.hash.as_bytes(), tx.hash.as_bytes())?;

                let receipt = Self::create_txn_receipt(
                    result,
                    tx.hash,
                    tx_index_in_block,
                    self.config.consensus.eth_block_gas_limit - gas_left,
                );

                let receipt_hash = receipt.compute_hash();
                debug!("During assembly in view: {}, transaction with hash: {:?} produced receipt: {:?}, receipt hash: {:?}", self.view.get_view(), tx.hash, receipt, receipt_hash);
                receipts_trie.insert(receipt_hash.as_bytes(), receipt_hash.as_bytes())?;

                tx_index_in_block += 1;
                updated_root_hash = state.root_hash()?;
                applied_txs.push(tx);
            }
        }

        // Grab and update early_proposal data in own scope to avoid multiple mutable references to Self
        {
            let (proposal, applied_txs, transactions_trie, receipts_trie) =
                self.early_proposal.as_mut().unwrap();

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

        // Restore the state to previous
        state.set_to_root(previous_state_root_hash.into());
        self.state = state;

        // as a future improvement, process the proposal before broadcasting it
        Ok(())
    }

    /// Called when consensus will accept our early_block.
    /// Either propose now or set timeout to allow for txs to come in.
    fn ready_for_block_proposal(&mut self) -> Result<Option<(Block, Vec<VerifiedTransaction>)>> {
        // Check if there's enough time to wait on a timeout and then propagate an empty block in the network before other participants trigger NewView
        let (
            time_since_last_view_change,
            exponential_backoff_timeout,
            minimum_time_left_for_empty_block,
        ) = self.get_consensus_timeout_params();

        if time_since_last_view_change + minimum_time_left_for_empty_block
            >= exponential_backoff_timeout
        {
            return self.propose_new_block();
        }

        // Reset the timeout and wake up again once it has been at least `empty_block_timeout` since
        // the last view change. At this point we should be ready to produce a new block.
        self.create_next_block_on_timeout = true;
        self.reset_timeout.send(
            self.config
                .consensus
                .empty_block_timeout
                .saturating_sub(Duration::from_millis(time_since_last_view_change)),
        )?;
        trace!(
            "will propose new proposal on timeout for view {}",
            self.view.get_view()
        );

        Ok(None)
    }
    /// Assembles a Pending block.
    fn assemble_pending_block_at(&self, state: &mut State) -> Result<Option<Block>> {
        // Start with highest canonical block
        let num = self
            .db
            .get_highest_canonical_block_number()?
            .context("no canonical blocks")?; // get highest canonical block number
        let block = self
            .get_canonical_block_by_number(num)?
            .context("missing canonical block")?; // retrieve highest canonical block

        // Generate early QC
        let early_qc = QuorumCertificate::new_with_identity(block.hash(), block.view());
        let parent = self
            .get_block(&early_qc.block_hash)?
            .context("missing parent block")?;

        // Ensure sane state
        let previous_state_root_hash = state.root_hash()?;
        if previous_state_root_hash != block.state_root_hash() {
            warn!(
                "state root hash mismatch, expected: {:?}, actual: {:?}",
                block.state_root_hash(),
                previous_state_root_hash
            );
            state.set_to_root(block.state_root_hash().into());
        }

        // Internal states
        let mut gas_left = self.config.consensus.eth_block_gas_limit;
        let mut receipts_trie = eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));
        let mut transactions_trie = eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));
        let mut updated_root_hash = state.root_hash()?;
        let mut tx_index_in_block = 0;
        let mut applied_transaction_hashes = Vec::<Hash>::new();

        // This is a partial header of a block that will be proposed with some transactions executed below.
        // It is needed so that each transaction is executed within proper block context (the block it belongs to)
        let executed_block_header = BlockHeader {
            view: self.view(),
            number: parent.header.number + 1,
            timestamp: SystemTime::max(SystemTime::now(), parent.header.timestamp),
            gas_limit: gas_left,
            ..BlockHeader::default()
        };

        // Retrieve a list of pending transactions
        let pending = self.transaction_pool.pending_hashes();

        for hash in pending.into_iter() {
            // First - check for time
            let (
                time_since_last_view_change,
                exponential_backoff_timeout,
                minimum_time_left_for_empty_block,
            ) = self.get_consensus_timeout_params();

            if time_since_last_view_change + minimum_time_left_for_empty_block
                >= exponential_backoff_timeout
            {
                break;
            }

            // Retrieve txn from the pool
            let Some(txn) = self.transaction_pool.get_transaction(hash) else {
                continue;
            };

            // Apply specific txn
            let result = Self::apply_transaction_at(
                state,
                self.db.clone(),
                txn.clone(),
                executed_block_header,
                inspector::noop(),
            )?;

            // Skip transactions whose execution resulted in an error
            let Some(result) = result else {
                continue;
            };

            // Second - check for gas
            gas_left = if let Some(g) = gas_left.checked_sub(result.gas_used()) {
                g
            } else {
                state.set_to_root(updated_root_hash.into());
                break;
            };

            // Do necessary work to assemble the transaction
            transactions_trie.insert(txn.hash.as_bytes(), txn.hash.as_bytes())?;

            let receipt = Self::create_txn_receipt(
                result,
                txn.hash,
                tx_index_in_block,
                self.config.consensus.eth_block_gas_limit - gas_left,
            );
            let receipt_hash = receipt.compute_hash();
            receipts_trie.insert(receipt_hash.as_bytes(), receipt_hash.as_bytes())?;

            tx_index_in_block += 1;
            updated_root_hash = state.root_hash()?;
            applied_transaction_hashes.push(txn.hash);
        }

        // Generate the pending proposal, with dummy data
        let proposal = Block::from_qc(
            self.secret_key,
            executed_block_header.view,
            executed_block_header.number,
            early_qc, // dummy QC for early proposal
            None,
            state.root_hash()?, // late state before rewards are applied
            Hash(transactions_trie.root_hash()?.into()),
            Hash(receipts_trie.root_hash()?.into()),
            applied_transaction_hashes,
            executed_block_header.timestamp,
            executed_block_header.gas_limit - gas_left,
            executed_block_header.gas_limit,
        );

        // Return the pending block
        Ok(Some(proposal))
    }

    /// Produces the Proposal block.
    /// It must return a final Proposal with correct QC, regardless of whether it is empty or not.
    fn propose_new_block(&mut self) -> Result<Option<(Block, Vec<VerifiedTransaction>)>> {
        // We expect early_proposal to exist already but try create incase it doesn't
        self.early_proposal_assemble_at(None)?;
        let (pending_block, applied_txs, _, _) = self.early_proposal.take().unwrap(); // safe to unwrap due to check above

        // intershard transactions are not meant to be broadcast
        let (mut broadcasted_transactions, opaque_transactions): (Vec<_>, Vec<_>) = applied_txs
            .clone()
            .into_iter()
            .partition(|tx| !matches!(tx.tx, SignedTransaction::Intershard { .. }));
        // however, for the transactions that we are NOT broadcasting, we re-insert
        // them into the pool - this is because upon broadcasting the proposal, we will
        // have to re-execute it ourselves (in order to vote on it) and thus will
        // need those transactions again
        for tx in opaque_transactions {
            let account_nonce = self.state.get_account(tx.signer)?.nonce;
            self.transaction_pool.insert_transaction(tx, account_nonce);
        }

        // finalise the proposal
        let Some(final_block) = self.early_proposal_finish_at(pending_block)? else {
            // Do not Propose.
            // Recover the proposed transactions into the pool.
            while let Some(txn) = broadcasted_transactions.pop() {
                self.transaction_pool.insert_ready_transaction(txn);
            }
            return Ok(None);
        };

        trace!(proposal_hash = ?final_block.hash(), ?final_block.header.view, ?final_block.header.number, "######### proposing block");

        Ok(Some((final_block, broadcasted_transactions)))
    }

    /// Insert transaction and add to early_proposal if possible.
    pub fn handle_new_transaction(&mut self, txn: SignedTransaction) -> Result<TxAddResult> {
        let verified = if let Ok(val) = txn.verify() {
            val
        } else {
            return Ok(TxAddResult::CannotVerifySignature);
        };
        let inserted = self.new_transaction(verified)?;
        if let TxAddResult::AddedToMempool = &inserted {
            if self.create_next_block_on_timeout && self.early_proposal.is_some() {
                info!("add transaction to early proposal {}", self.view.get_view());
                self.early_proposal_apply_transactions()?;
            }
        }
        Ok(inserted)
    }

    /// Provides a preview of the early proposal.
    pub fn get_pending_block(&self) -> Result<Option<Block>> {
        let mut state = self.state.clone();

        let Some(pending_block) = self.assemble_pending_block_at(&mut state)? else {
            return Ok(None);
        };

        Ok(Some(pending_block))
    }

    fn are_we_leader_for_view(&mut self, parent_hash: Hash, view: u64) -> bool {
        match self.leader_for_view(parent_hash, view) {
            Some(leader) => leader == self.public_key(),
            None => false,
        }
    }

    fn leader_for_view(&mut self, parent_hash: Hash, view: u64) -> Option<NodePublicKey> {
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
            return Err(anyhow!("parent block not found: {:?}", parent_hash));
        };

        let parent_root_hash = parent.state_root_hash();

        let state = self.state.at_root(parent_root_hash.into());

        let committee = state.get_stakers()?;

        Ok(committee)
    }

    pub fn new_view(
        &mut self,
        new_view: NewView,
    ) -> Result<Option<(Block, Vec<VerifiedTransaction>)>> {
        trace!("Received new view for height: {:?}", new_view.view);

        // The leader for this view should be chosen according to the parent of the highest QC
        // What happens when there are multiple QCs with different parents?
        // if we are not the leader of the round in which the vote counts
        if !self.are_we_leader_for_view(new_view.qc.block_hash, new_view.view) {
            trace!(new_view.view, "skipping new view, not the leader");
            return Ok(None);
        }
        // if the vote is too old and does not count anymore
        if new_view.view < self.view.get_view() {
            trace!(new_view.view, "Received a vote which is too old for us, discarding. Our view is: {} and new_view is: {}", self.view.get_view(), new_view.view);
            return Ok(None);
        }

        // Get the committee for the qc hash (should be highest?) for this view
        let committee: Vec<_> = self.committee_for_hash(new_view.qc.block_hash)?;
        // verify the sender's signature on the block hash
        let Some((index, public_key)) = committee
            .iter()
            .enumerate()
            .find(|(_, &public_key)| public_key == new_view.public_key)
        else {
            debug!("ignoring new view from unknown node (buffer?) - committee size is : {:?} hash is: {:?} high hash is: {:?}", committee.len(), new_view.qc.block_hash, self.high_qc.block_hash);
            return Ok(None);
        };

        new_view.verify(*public_key)?;

        // check if the sender's qc is higher than our high_qc or even higher than our view
        self.update_high_qc_and_view(false, new_view.qc)?;

        let NewViewVote {
            mut signatures,
            mut cosigned,
            mut cosigned_weight,
            mut qcs,
        } = self
            .new_views
            .remove(&new_view.view)
            .unwrap_or_else(|| NewViewVote {
                signatures: Vec::new(),
                cosigned: bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE],
                cosigned_weight: 0,
                qcs: Vec::new(),
            });

        let mut supermajority = false;

        // if the vote is new, store it
        if !cosigned[index] {
            cosigned.set(index, true);
            signatures.push(new_view.signature);
            let Some(weight) = self.state.get_stake(new_view.public_key)? else {
                return Err(anyhow!("vote from validator without stake"));
            };
            cosigned_weight += weight.get();
            qcs.push(new_view.qc);

            supermajority = cosigned_weight * 3 > self.total_weight(&committee) * 2;

            let num_signers = signatures.len();
            let current_view = self.view.get_view();
            trace!(
                num_signers,
                cosigned_weight,
                supermajority,
                current_view,
                new_view.view,
                "storing vote for new view"
            );
            if supermajority {
                if self.view.get_view() < new_view.view {
                    info!(
                        "forcibly updating view to {} as majority is ahead",
                        new_view.view
                    );
                    self.view.set_view(new_view.view);
                }

                // if we are already in the round in which the vote counts and have reached supermajority we can propose a block
                if new_view.view == self.view.get_view() {
                    // todo: the aggregate qc is an aggregated signature on the qcs, view and validator index which can be batch verified
                    let agg =
                        self.aggregate_qc_from_indexes(new_view.view, qcs, &signatures, cosigned)?;

                    trace!(
                        view = self.view.get_view(),
                        "######### creating proposal block from new view"
                    );

                    // We now have a valid aggQC so can create early_block with it
                    self.early_proposal_assemble_at(Some(agg))?;

                    // as a future improvement, process the proposal before broadcasting it
                    return self.ready_for_block_proposal();

                    // we don't want to keep the collected votes if we proposed a new block
                    // we should remove the collected votes if we couldn't reach supermajority within the view
                }
            }
        }
        if !supermajority {
            self.new_views.insert(
                new_view.view,
                NewViewVote {
                    signatures,
                    cosigned,
                    cosigned_weight,
                    qcs,
                },
            );
        }

        Ok(None)
    }

    /// Returns (flag, outcome).
    /// flag is true if the transaction was newly added to the pool - ie. if it validated correctly and has not been seen before.
    pub fn new_transaction(&mut self, txn: VerifiedTransaction) -> Result<TxAddResult> {
        if self.db.contains_transaction(&txn.hash)? {
            debug!("Transaction {:?} already in mempool", txn.hash);
            return Ok(TxAddResult::Duplicate(txn.hash));
        }

        let account = self.state.get_account(txn.signer)?;
        let eth_chain_id = self.config.eth_chain_id;

        let validation_result = txn.tx.validate(
            &account,
            self.config.consensus.eth_block_gas_limit,
            eth_chain_id,
        )?;
        if !validation_result.is_ok() {
            debug!(
                "Unable to validate txn with hash: {:?}, from: {:?}, nonce: {:?} : {:?}",
                txn.hash,
                txn.signer,
                txn.tx.nonce(),
                validation_result,
            );
            return Ok(TxAddResult::ValidationFailed(validation_result));
        }

        let txn_hash = txn.hash;

        let insert_result = self.transaction_pool.insert_transaction(txn, account.nonce);
        if insert_result.was_added() {
            let _ = self.new_transaction_hashes.send(txn_hash);

            // Avoid cloning the transaction aren't any subscriptions to send it to.
            if self.new_transactions.receiver_count() != 0 {
                // Clone the transaction from the pool, because we moved it in.
                let txn = self
                    .transaction_pool
                    .get_transaction(txn_hash)
                    .ok_or_else(|| anyhow!("transaction we just added is missing"))?
                    .clone();
                let _ = self.new_transactions.send(txn);
            }
        }
        Ok(insert_result)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<VerifiedTransaction>> {
        Ok(self
            .db
            .get_transaction(&hash)?
            .map(|tx| tx.verify())
            .transpose()?
            .or_else(|| self.transaction_pool.get_transaction(hash).cloned()))
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
        let Some(new_high_qc_block) = self.block_store.get_block(new_high_qc.block_hash)? else {
            // We don't set high_qc to a qc if we don't have its block.
            warn!("Recieved potential high QC but didn't have the corresponding block");
            return Ok(());
        };

        let new_high_qc_block_view = new_high_qc_block.view();

        if self.high_qc.block_hash == Hash::ZERO {
            trace!("received high qc, self high_qc is currently uninitialized, setting to the new one.");
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
            if from_agg || new_high_qc_block_view > current_high_qc_view {
                trace!(
                    "updating view from {} to {}, high QC view is {}",
                    self.view.get_view(),
                    new_high_qc_block_view + 1,
                    current_high_qc_view,
                );
                self.db.set_high_qc(new_high_qc)?;
                self.high_qc = new_high_qc;
                if new_high_qc_block_view >= self.view.get_view() {
                    self.view.set_view(new_high_qc_block_view + 1);
                }
            }
        }

        Ok(())
    }

    fn aggregate_qc_from_indexes(
        &self,
        view: u64,
        qcs: Vec<QuorumCertificate>,
        signatures: &[NodeSignature],
        cosigned: BitArray,
    ) -> Result<AggregateQc> {
        assert_eq!(qcs.len(), signatures.len());

        Ok(AggregateQc {
            signature: NodeSignature::aggregate(signatures)?,
            cosigned,
            view,
            qcs,
        })
    }

    fn qc_from_bits(
        &self,
        block_hash: Hash,
        signatures: &[NodeSignature],
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
                warn!("Missing block when traversing to find ancestor! Current parent hash: {:?} {:?}", current.parent_hash(), current);
                return Err(MissingBlockError::from(current.parent_hash()).into());
            };
            current = next;
        }

        Ok(current.view() == 0 || current.hash() == ancestor.hash())
    }

    fn check_safe_block(&mut self, proposal: &Block, during_sync: bool) -> Result<bool> {
        let Some(qc_block) = self.get_block(&proposal.parent_hash())? else {
            trace!("could not get qc for block: {}", proposal.parent_hash());
            return Ok(false);
        };
        // We don't vote on blocks older than our view
        let outdated = proposal.view() < self.view.get_view();
        match proposal.agg {
            // we check elsewhere that qc is the highest among the qcs in the agg
            Some(_) => match self.block_extends_from(proposal, &qc_block) {
                Ok(true) => {
                    self.check_and_commit(proposal)?;
                    trace!("check block aggregate is outdated? {}", outdated);
                    Ok(!outdated || during_sync)
                }
                Ok(false) => {
                    trace!("block does not extend from parent");
                    Ok(false)
                }
                Err(e) => {
                    trace!(?e, "error checking block extension");
                    Ok(false)
                }
            },
            None => {
                if proposal.view() == 0 || proposal.view() == qc_block.view() + 1 {
                    self.check_and_commit(proposal)?;

                    if outdated {
                        trace!(
                            "proposal is outdated: {} < {}",
                            proposal.view(),
                            self.view.get_view()
                        );
                    }

                    trace!("check block is outdated? {}", outdated);

                    Ok(!outdated || during_sync)
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

    fn finalize_view(&mut self, view: u64) -> Result<()> {
        self.finalized_view = view;
        self.db.set_latest_finalized_view(view)
    }

    /// Saves the finalized tip view, and runs all hooks for the newly finalized block
    fn finalize_block(&mut self, block: Block) -> Result<()> {
        trace!(
            "Finalizing block {} at view {} num {}",
            block.hash(),
            block.view(),
            block.number()
        );
        self.finalize_view(block.view())?;

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

        if self.block_is_first_in_epoch(block.number()) && !block.is_genesis() {
            // TODO: handle epochs (#1140)

            if self.config.do_checkpoints
                && self.epoch_is_checkpoint(self.epoch_number(block.number()))
            {
                if let Some(checkpoint_path) = self.db.get_checkpoint_dir()? {
                    let parent =
                        self.db
                            .get_block_by_hash(&block.parent_hash())?
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
                            Ok::<_, anyhow::Error>(tx)
                        })
                        .collect::<Result<Vec<SignedTransaction>>>()?;
                    self.message_sender.send_message_to_coordinator(
                        InternalMessage::ExportBlockCheckpoint(
                            Box::new(block),
                            transactions,
                            Box::new(parent),
                            self.db.state_trie()?.clone(),
                            checkpoint_path,
                        ),
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Trigger a checkpoint, for debugging.
    /// Returns (file_name, block_hash). At some time after you call this function, hopefully a checkpoint will end up in the file
    pub fn checkpoint_at(&mut self, block_number: u64) -> Result<(String, String)> {
        let block = self
            .get_canonical_block_by_number(block_number)?
            .ok_or(anyhow!("No such block number {block_number}"))?;
        let parent = self
            .db
            .get_block_by_hash(&block.parent_hash())?
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
                Ok::<_, anyhow::Error>(tx)
            })
            .collect::<Result<Vec<SignedTransaction>>>()?;
        let checkpoint_dir = self
            .db
            .get_checkpoint_dir()?
            .ok_or(anyhow!("No checkpoint directory configured"))?;
        let file_name = db::get_checkpoint_filename(checkpoint_dir.clone(), &block)?;
        let hash = block.hash();
        self.message_sender
            .send_message_to_coordinator(InternalMessage::ExportBlockCheckpoint(
                Box::new(block),
                transactions,
                Box::new(parent),
                self.db.state_trie()?.clone(),
                checkpoint_dir,
            ))?;
        Ok((file_name.display().to_string(), hash.to_string()))
    }

    /// Check the validity of a block. Returns `Err(_, true)` if this block could become valid in the future and
    /// `Err(_, false)` if this block could never be valid.
    fn check_block(&self, block: &Block, during_sync: bool) -> Result<(), (anyhow::Error, bool)> {
        block.verify_hash().map_err(|e| (e, false))?;

        if block.view() == 0 {
            // We only check a block if we receive it from an external source. We obviously already have the genesis
            // block, so we aren't ever expecting to receive it.
            return Err((anyhow!("tried to check genesis block"), false));
        }

        let Some(parent) = self
            .get_block(&block.parent_hash())
            .map_err(|e| (e, false))?
        else {
            warn!(
                "Missing parent block while trying to check validity of block {}",
                block.number()
            );
            return Err((MissingBlockError::from(block.parent_hash()).into(), true));
        };

        let Some(finalized_block) = self
            .get_block_by_view(self.finalized_view)
            .map_err(|e| (e, false))?
        else {
            return Err((MissingBlockError::from(self.finalized_view).into(), false));
        };
        if block.view() < finalized_block.view() {
            return Err((
                anyhow!(
                    "block is too old: view is {} but we have finalized {}",
                    block.view(),
                    finalized_block.view()
                ),
                false,
            ));
        }

        // Derive the proposer from the block's view
        let proposer = self.leader_at_block(&parent, block.view()).unwrap();

        // Verify the proposer's signature on the block
        let verified = proposer
            .public_key
            .verify(block.hash().as_bytes(), block.signature());

        let committee = self
            .state
            .get_stakers_at_block(&parent)
            .map_err(|e| (e, false))?;

        if verified.is_err() {
            info!(?block, "Unable to verify block = ");
            return Err((anyhow!("invalid block signature found! block hash: {:?} block view: {:?} committee len {:?}", block.hash(), block.view(), committee.len()), false));
        }

        // Check if the co-signers of the block's QC represent the supermajority.
        self.check_quorum_in_bits(
            &block.header.qc.cosigned,
            &committee,
            parent.state_root_hash(),
        )
        .map_err(|e| (e, false))?;

        // Verify the block's QC signature - note the parent should be the committee the QC
        // was signed over.
        self.verify_qc_signature(&block.header.qc, committee.clone())
            .map_err(|e| (e, false))?;
        if let Some(agg) = &block.agg {
            // Check if the signers of the block's aggregate QC represent the supermajority
            self.check_quorum_in_indices(&agg.cosigned, &committee)
                .map_err(|e| (e, false))?;
            // Verify the aggregate QC's signature
            self.batch_verify_agg_signature(agg, &committee)
                .map_err(|e| (e, false))?;
        }

        // Retrieve the highest among the aggregated QCs and check if it equals the block's QC.
        let block_high_qc = self.get_high_qc_from_block(block).map_err(|e| (e, false))?;
        let Some(block_high_qc_block) = self
            .get_block(&block_high_qc.block_hash)
            .map_err(|e| (e, false))?
        else {
            warn!("missing finalized block4");
            return Err((
                MissingBlockError::from(block_high_qc.block_hash).into(),
                false,
            ));
        };
        // Prevent the creation of forks from the already committed chain
        if block_high_qc_block.view() < finalized_block.view() {
            warn!(
                "invalid block - high QC view is {} while finalized is {}. Our High QC: {}, block: {:?}",
                block_high_qc_block.view(),
                finalized_block.view(),
                self.high_qc,
                block);
            return Err((
                anyhow!(
                    "invalid block - high QC view is {} while finalized is {}",
                    block_high_qc_block.view(),
                    finalized_block.view()
                ),
                false,
            ));
        }

        // This block's timestamp must be greater than or equal to the parent block's timestamp.
        if block.timestamp() < parent.timestamp() {
            return Err((anyhow!("timestamp decreased from parent"), false));
        }

        // This block's timestamp should be at most `self.allowed_timestamp_skew` away from the current time. Note this
        // can be either forwards or backwards in time.
        let difference = block
            .timestamp()
            .elapsed()
            .unwrap_or_else(|err| err.duration());
        if !during_sync && difference > self.config.allowed_timestamp_skew {
            return Err((
                anyhow!(
                    "timestamp difference for block {} greater than allowed skew: {difference:?}",
                    block.view()
                ),
                false,
            ));
        }

        // Blocks must be in sequential order
        if block.header.number != parent.header.number + 1 {
            return Err((
                anyhow!(
                    "block number is not sequential: {} != {} + 1",
                    block.header.number,
                    parent.header.number
                ),
                false,
            ));
        }

        if !self
            .block_extends_from(block, &finalized_block)
            .map_err(|e| (e, false))?
        {
            warn!(
                "invalid block {:?}, does not extend finalized block {:?} our head is {:?}",
                block,
                finalized_block,
                self.head_block()
            );

            return Err((
                anyhow!("invalid block, does not extend from finalized block"),
                false,
            ));
        }
        Ok(())
    }

    // Receives availability and passes it on to the block store.
    pub fn receive_block_availability(
        &mut self,
        from: PeerId,
        availability: &Option<Vec<BlockStrategy>>,
    ) -> Result<()> {
        trace!(
            "Received block availability from {:?} avail {:?}",
            from,
            availability
        );
        self.block_store.update_availability(from, availability)?;
        Ok(())
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
        self.block_store
            .received_process_proposal(proposal.header.view);
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

    fn add_block(&mut self, from: Option<PeerId>, block: Block) -> Result<()> {
        let hash = block.hash();
        debug!(?from, ?hash, ?block.header.view, ?block.header.number, "added block");
        let _ = self.new_blocks.send(block.header);
        // We may have child blocks; process them too.
        self.block_store
            .process_block(from, block)?
            .into_iter()
            .try_for_each(|(from_id, child_proposal)| -> Result<()> {
                // The only reason this can fail is permanent failure of the messaging mechanism, so
                // propagate it back here.
                // Mark this block in the cache as "we're about to process this one"
                let view = child_proposal.header.view;
                self.message_sender.send_external_message(
                    self.peer_id(),
                    ExternalMessage::ProcessProposal(ProcessProposal {
                        from: from_id.to_bytes(),
                        block: child_proposal,
                    }),
                )?;
                self.block_store.expect_process_proposal(view);
                Ok(())
            })?;
        Ok(())
    }

    fn block_is_first_in_epoch(&self, number: u64) -> bool {
        number % self.config.consensus.blocks_per_epoch == 0
    }

    fn epoch_number(&self, block_number: u64) -> u64 {
        // This will need additonal tracking if we ever allow blocks_per_epoch to be changed
        block_number / self.config.consensus.blocks_per_epoch
    }

    fn epoch_is_checkpoint(&self, epoch_number: u64) -> bool {
        epoch_number % self.config.consensus.epochs_per_checkpoint == 0
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
        self.block_store.get_block(*key)
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        self.block_store.get_block_by_view(view)
    }

    pub fn get_canonical_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        self.block_store.get_canonical_block_by_number(number)
    }

    pub fn view(&self) -> u64 {
        self.view.get_view()
    }

    pub fn finalized_view(&self) -> u64 {
        self.finalized_view
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn state_at(&self, number: u64) -> Result<Option<State>> {
        Ok(self
            .block_store
            .get_canonical_block_by_number(number)?
            .map(|block| self.state.at_root(block.state_root_hash().into())))
    }

    pub fn try_get_state_at(&self, number: u64) -> Result<State> {
        self.state_at(number)?
            .ok_or_else(|| anyhow!("No block at height {number}"))
    }

    fn get_highest_from_agg(&self, agg: &AggregateQc) -> Result<QuorumCertificate> {
        agg.qcs
            .iter()
            .map(|qc| (qc, self.get_block(&qc.block_hash)))
            .try_fold(None, |acc, (qc, block)| {
                let block = block?.ok_or_else(|| anyhow!("missing block"))?;
                if let Some((_, acc_view)) = acc {
                    if acc_view < block.view() {
                        Ok::<_, anyhow::Error>(Some((qc, block.view())))
                    } else {
                        Ok(acc)
                    }
                } else {
                    Ok(Some((qc, block.view())))
                }
            })?
            .ok_or_else(|| anyhow!("no qcs in agg"))
            .map(|(qc, _)| *qc)
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
    ) -> Result<()> {
        let parent_state = self.state.at_root(parent_state_hash.into());

        let (total_weight, cosigned_sum) = committee
            .iter()
            .enumerate()
            .map(|(i, public_key)| {
                (
                    i,
                    parent_state.get_stake(*public_key).unwrap().unwrap().get(),
                )
            })
            .fold((0, 0), |(total_weight, cosigned_sum), (i, stake)| {
                (
                    total_weight + stake,
                    cosigned_sum + cosigned[i].then_some(stake).unwrap_or_default(),
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
    ) -> Result<()> {
        let cosigned_sum: u128 = signers
            .iter()
            .enumerate()
            .map(|(i, bit)| {
                if *bit {
                    let public_key = committee.get(i).unwrap();
                    let stake = self.state.get_stake(*public_key).unwrap().unwrap();
                    stake.get()
                } else {
                    0
                }
            })
            .sum();

        if cosigned_sum * 3 <= self.total_weight(committee) * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    pub fn leader_at_block(&self, block: &Block, view: u64) -> Option<Validator> {
        if let Some(CachedLeader {
            block_number: cached_block_number,
            view: cached_view,
            next_leader,
        }) = *self.latest_leader_cache.borrow()
        {
            if cached_block_number == block.number() && cached_view == view {
                return Some(next_leader);
            }
        }

        let Ok(state_at) = self.try_get_state_at(block.number()) else {
            return None;
        };

        let public_key = state_at.leader(view).unwrap();
        let peer_id = state_at.get_peer_id(public_key).unwrap().unwrap();

        Some(Validator {
            public_key,
            peer_id,
        })
    }

    fn total_weight(&self, committee: &[NodePublicKey]) -> u128 {
        committee
            .iter()
            .map(|&pub_key| {
                let stake = self.state.get_stake(pub_key).unwrap().unwrap();
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
            "Dealing with fork: from block {} (height {}), back to block {} (height {})",
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

            trace!("Reverting block {head_block:?}");
            // block store doesn't require anything, it will just hold blocks that may now be invalid

            // State is easily set - must be to the parent block, though
            trace!(
                "Setting state to: {} aka block: {parent_block:?}",
                parent_block.state_root_hash()
            );
            self.state
                .set_to_root(parent_block.state_root_hash().into());

            // Ensure the transaction pool is consistent by recreating it. This is moderately costly, but forks are
            // rare.
            let existing_txns = self.transaction_pool.drain();

            for txn in existing_txns {
                let account_nonce = self.state.get_account(txn.signer)?.nonce;
                self.transaction_pool.insert_transaction(txn, account_nonce);
            }

            // block transactions need to be removed from self.transactions and re-injected
            for tx_hash in &head_block.transactions {
                let orig_tx = self.get_transaction_by_hash(*tx_hash).unwrap().unwrap();

                // Insert this unwound transaction back into the transaction pool.
                let account_nonce = self.state.get_account(orig_tx.signer)?.nonce;
                self.transaction_pool
                    .insert_transaction(orig_tx, account_nonce);
            }
            // then purge them all from the db, including receipts and indexes
            self.db
                .remove_transactions_executed_in_block(&head_block.hash())?;

            // this block is no longer in the main chain
            self.db.mark_block_as_non_canonical(head_block.hash())?;
        }

        // Now, we execute forward from the common ancestor to the new block parent which can
        // be required in rare cases.
        // We have the chain of blocks from the ancestor upwards to the proposed block via walking back.
        while self.head_block().hash() != block.parent_hash() {
            trace!("Advancing the head block to prepare for proposed block fork.");
            trace!("Head block: {:?}", self.head_block());
            trace!("desired block hash: {}", block.parent_hash());

            let desired_block_height = self.head_block().number() + 1;
            // Pointer to parent of head block
            let mut block_pointer = self
                .get_block(&block.parent_hash())?
                .ok_or_else(|| anyhow!("missing block when advancing head block pointer"))?;

            // If the parent of the proposed
            if block_pointer.header.number < desired_block_height {
                panic!("block height mismatch when advancing head block pointer");
            }

            while block_pointer.header.number != desired_block_height {
                block_pointer = self
                    .get_block(&block_pointer.parent_hash())?
                    .ok_or_else(|| anyhow!("missing block when advancing head block pointer"))?;
            }

            // We now have the block pointer at the desired height, we can apply it.
            trace!("Fork execution of block: {block_pointer:?}");
            let transactions = block_pointer.transactions.clone();
            let transactions = transactions
                .iter()
                .map(|tx_hash| self.get_transaction_by_hash(*tx_hash).unwrap().unwrap().tx)
                .collect();
            let committee: Vec<_> = self.state.get_stakers_at_block(&block_pointer)?;
            self.execute_block(None, &block_pointer, transactions, &committee)?;
        }

        Ok(())
    }

    fn execute_block(
        &mut self,
        from: Option<PeerId>,
        block: &Block,
        transactions: Vec<SignedTransaction>,
        committee: &[NodePublicKey],
    ) -> Result<()> {
        debug!("Executing block: {:?}", block.header.hash);

        let parent = self
            .get_block(&block.parent_hash())?
            .ok_or_else(|| anyhow!("missing parent block when executing block!"))?;

        if !transactions.is_empty() {
            trace!("applying {} transactions to state", transactions.len());
        }

        let mut verified_txns = Vec::new();

        // We re-inject any missing Intershard transactions (or really, any missing
        // transactions) from our mempool. If any txs are unavailable in both the
        // message or locally, the proposal cannot be applied
        for (idx, tx_hash) in block.transactions.iter().enumerate() {
            // Prefer to insert verified txn from pool. This is faster.
            let txn = match self.transaction_pool.pop_transaction(*tx_hash) {
                Some(txn) => txn,
                _ => match transactions
                    .get(idx)
                    .map(|sig_tx| sig_tx.clone().verify())
                    .transpose()?
                {
                    // Otherwise, recover txn from proposal. This is slower.
                    Some(txn) if txn.hash == *tx_hash => txn,
                    _ => {
                        warn!("Proposal {} at view {} referenced a transaction {} that was neither included in the broadcast nor found locally - cannot apply block", block.hash(), block.view(), tx_hash);
                        return Ok(());
                    }
                },
            };
            verified_txns.push(txn);
        }

        let mut block_receipts = Vec::new();
        let mut cumulative_gas_used = EvmGas(0);
        let mut receipts_trie = eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));
        let mut transactions_trie = eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));

        let transaction_hashes = verified_txns
            .iter()
            .map(|tx| format!("{:?}", tx.hash))
            .join(",");

        for (tx_index, txn) in verified_txns.into_iter().enumerate() {
            self.new_transaction(txn.clone())?;
            let tx_hash = txn.hash;
            let mut inspector = TouchedAddressInspector::default();
            let result = self
                .apply_transaction(txn.clone(), block.header, &mut inspector)?
                .ok_or_else(|| anyhow!("proposed transaction failed to execute"))?;
            self.transaction_pool.mark_executed(&txn);
            for address in inspector.touched {
                self.db.add_touched_address(address, tx_hash)?;
            }

            let gas_used = result.gas_used();
            cumulative_gas_used += gas_used;

            if cumulative_gas_used > block.gas_limit() {
                warn!("Cumulative gas used by executing transactions exceeded block limit!");
                return Ok(());
            }

            let receipt = Self::create_txn_receipt(result, tx_hash, tx_index, cumulative_gas_used);

            let receipt_hash = receipt.compute_hash();

            debug!("During execution in view: {}, transaction with hash: {:?} produced receipt: {:?}, receipt hash: {:?}", self.view.get_view(), tx_hash, receipt, receipt_hash);
            receipts_trie
                .insert(receipt_hash.as_bytes(), receipt_hash.as_bytes())
                .unwrap();

            transactions_trie
                .insert(tx_hash.as_bytes(), tx_hash.as_bytes())
                .unwrap();

            info!(?receipt, "applied transaction {:?}", receipt);
            block_receipts.push((receipt, tx_index));
        }

        if cumulative_gas_used != block.gas_used() {
            warn!("Cumulative gas used by executing all transactions: {cumulative_gas_used} is different that the one provided in the block: {}", block.gas_used());
            return Ok(());
        }

        let receipts_root_hash: Hash = receipts_trie.root_hash()?.into();
        if block.header.receipts_root_hash != receipts_root_hash {
            warn!(
                "Block number: {}, Receipt root mismatch. Specified in block: {} vs computed: {}, txn_hashes: {}",
                block.number(), block.header.receipts_root_hash, receipts_root_hash, transaction_hashes
            );
            return Ok(());
        }

        let transactions_root_hash: Hash = transactions_trie.root_hash()?.into();
        if block.header.transactions_root_hash != transactions_root_hash {
            warn!(
                "Block number: {}, Transactions root mismatch. Specified in block: {} vs computed: {}, txn_hashes: {}",
                block.number(), block.header.transactions_root_hash, transactions_root_hash, transaction_hashes
            );
            return Ok(());
        }

        // Apply rewards after executing transactions but with the committee members from the previous block
        let proposer = self.leader_at_block(&parent, block.view()).unwrap();
        let config = &self.config.consensus;
        Self::apply_rewards_late_at(
            parent.state_root_hash(),
            &mut self.state,
            config,
            committee,
            proposer.public_key,
            block.view(),
            &block.header.qc.cosigned,
        )?;

        // ZIP-9: Sink gas to zero account
        self.state.mutate_account(Address::ZERO, |a| {
            a.balance = a
                .balance
                .checked_add(block.gas_used().0 as u128)
                .ok_or(anyhow!("Overflow occured in zero account balance"))?;
            Ok(())
        })?;

        if self.state.root_hash()? != block.state_root_hash() {
            warn!(
                "State root hash mismatch! Our state hash: {}, block hash: {:?} block prop: {:?}, txn_hashes: {}",
                self.state.root_hash()?,
                block.state_root_hash(),
                block,
                transaction_hashes
            );
            return Err(anyhow!(
                "state root hash mismatch, expected: {:?}, actual: {:?}",
                block.state_root_hash(),
                self.state.root_hash()
            ));
        }

        for (receipt, tx_index) in &mut block_receipts {
            receipt.block_hash = block.hash();
            // Avoid cloning the receipt if there are no subscriptions to send it to.
            if self.receipts.receiver_count() != 0 {
                let _ = self.receipts.send((receipt.clone(), *tx_index));
            }
        }

        // Important - only add blocks we are going to execute because they can potentially
        // overwrite the mapping of block height to block, which there should only be one of.
        // for example, this HAS to be after the deal with fork call
        if !self.db.contains_block(&block.hash())? {
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

    pub fn report_outgoing_message_failure(
        &mut self,
        failure: OutgoingMessageFailure,
    ) -> Result<()> {
        self.block_store.report_outgoing_message_failure(failure)
    }

    pub fn tick(&mut self) -> Result<()> {
        trace!("consensus::tick()");
        trace!("request_missing_blocks from timer");

        // Drives the block fetching state machine - see docs/fetching_blocks.md
        if self.block_store.request_missing_blocks()? {
            // We're syncing..
            // Is it likely that the next thing in the buffer could be the next block?
            let likely_blocks = self.block_store.next_proposals_if_likely()?;
            if likely_blocks.is_empty() {
                trace!("no blocks buffered");
                // If there are no next blocks buffered, someone may well have lied to us about
                // where the gaps in the view range are. This should be a rare occurrence, so in
                // lieu of timing it out, just zap the view range gap and we'll take the hit on
                // any rerequests.
                self.block_store.delete_empty_view_range_cache();
            } else {
                likely_blocks.into_iter().for_each(|(from, block)| {
                    trace!(
                        "buffer may contain the next block - {0:?} v={1} n={2}",
                        block.hash(),
                        block.view(),
                        block.number()
                    );
                    // Ignore errors here - just carry on and wait for re-request to clean up.
                    let view = block.view();
                    let _ = self.message_sender.send_external_message(
                        self.peer_id(),
                        ExternalMessage::ProcessProposal(ProcessProposal {
                            from: from.to_bytes(),
                            block,
                        }),
                    );
                    self.block_store.expect_process_proposal(view);
                });
            }
        } else {
            trace!("not syncing ...");
        }
        Ok(())
    }

    pub fn buffer_proposal(&mut self, from: PeerId, proposal: Proposal) -> Result<()> {
        self.block_store.buffer_proposal(from, proposal)?;
        Ok(())
    }

    pub fn buffer_lack_of_proposals(
        &mut self,
        from_view: u64,
        proposals: &Vec<Proposal>,
    ) -> Result<()> {
        self.block_store
            .buffer_lack_of_proposals(from_view, proposals)
    }
}
