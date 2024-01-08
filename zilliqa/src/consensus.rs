use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
    error::Error,
    fmt::Display,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use bitvec::bitvec;
use ethabi::{Event, Log, RawLog};
use libp2p::PeerId;
use primitive_types::H256;
use rand::{prelude::IteratorRandom, rngs::SmallRng};
use serde::{Deserialize, Serialize};
use tracing::*;

use crate::{
    block_store::BlockStore,
    cfg::NodeConfig,
    contracts,
    crypto::{Hash, NodePublicKey, NodeSignature, SecretKey},
    db::Db,
    exec::{TouchedAddressEventListener, TransactionApplyResult},
    message::{
        AggregateQc, BitSlice, BitVec, Block, BlockHeader, BlockRef, Committee, ExternalMessage,
        InternalMessage, NewView, Proposal, QuorumCertificate, Vote,
    },
    node::MessageSender,
    state::{contract_addr, Address, State},
    time::SystemTime,
    transaction::{SignedTransaction, TransactionReceipt, VerifiedTransaction},
};

#[derive(Debug)]
struct NewViewVote {
    signatures: Vec<NodeSignature>,
    signers: Vec<u16>,
    cosigned: BitVec,
    cosigned_weight: u128,
    qcs: Vec<QuorumCertificate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Validator {
    pub public_key: NodePublicKey,
    pub peer_id: PeerId,
    pub weight: u128, // Validators are weighted by their stake for leader selection and also signing power
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

#[derive(Debug, Clone)]
struct TxnOrder {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub hash: Hash,
    pub retries: u64,
}

impl TxnOrder {
    fn new(hash: Hash, txn: &SignedTransaction) -> Self {
        let txn = txn.clone().into_transaction();
        TxnOrder {
            nonce: txn.nonce(),
            gas_price: txn.max_fee_per_gas(),
            gas_limit: txn.gas_limit(),
            hash,
            retries: 0,
        }
    }
}

impl PartialEq for TxnOrder {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.gas_price == other.gas_price
            && self.gas_limit == other.gas_limit
            && self.hash == other.hash
    }
}

impl Eq for TxnOrder {}

// Implement a custom ordering for TxnOrder
impl Ord for TxnOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.hash == other.hash {
            warn!("TXnOrder hash collision {:?} vs {:?}", self, other);
            return Ordering::Equal;
        }

        let nonce_ordering = other.nonce.cmp(&self.nonce);
        if nonce_ordering == Ordering::Equal {
            // If nonce is equal, compare by gas_price * fee (desire higher)
            let self_fee = self.gas_price;
            let other_fee = other.gas_price;
            self_fee.cmp(&other_fee)
        } else {
            nonce_ordering
        }
    }
}

impl PartialOrd for TxnOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The consensus algorithm is pipelined fast-hotstuff, as given in this paper: https://arxiv.org/pdf/2010.11454.pdf
///
/// The algorithm can be condensed down into the following explaination:
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
    pub block_store: BlockStore,
    votes: BTreeMap<Hash, (Vec<NodeSignature>, BitVec, u128, bool)>,
    new_views: BTreeMap<u64, NewViewVote>,
    high_qc: QuorumCertificate,
    view: View,
    finalized_view: u64,
    /// Peers that have appeared between the last view and this one. They will be added to the committee before the next view.
    pending_peers: Vec<Validator>,
    /// Transactions that have been broadcasted by the network, but not yet executed. Transactions will be removed from this map once they are executed.
    new_transactions: BTreeMap<Hash, VerifiedTransaction>,
    /// The account store.
    state: State,
    /// The persistence database
    db: Arc<Db>,
    /// Transactions ordered by priority, map of address of TXn (from account) to ordered TXns to be executed.
    new_transactions_priority: BTreeMap<Address, BinaryHeap<TxnOrder>>,
    // PRNG - non-cryptographically secure, but we don't need that here
    rng: SmallRng,
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
                // todo: this can happen if agg is true - how to handle?
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
        db: Arc<Db>,
    ) -> Result<Self> {
        trace!(
            "Opening database in {:?} for shard {}",
            config.data_dir,
            config.eth_chain_id
        );

        let mut block_store = BlockStore::new(db.clone(), message_sender.clone())?;

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
            State::new_at_root(db.state_trie()?, H256(latest_block.state_root_hash().0))
        } else {
            trace!("Contructing new state from genesis");
            State::new_with_genesis(db.state_trie()?, config.consensus.clone())?
        };

        let (latest_block, latest_block_view, latest_block_number, latest_block_hash) =
            match latest_block {
                Some(l) => (Some(l.clone()), l.view(), l.number(), l.hash()),
                None => match (
                    config.consensus.genesis_committee.len(),
                    config.consensus.genesis_hash,
                ) {
                    (0, Some(hash)) => {
                        block_store.request_block(hash)?;
                        (None, 0, 0, hash)
                    }
                    (1, hash) => {
                        let (public_key, peer_id) = config.consensus.genesis_committee[0];
                        let genesis_validator = Validator {
                            public_key,
                            peer_id,
                            weight: 100,
                        };
                        let genesis =
                            Block::genesis(Committee::new(genesis_validator), state.root_hash()?);
                        if let Some(hash) = hash {
                            if genesis.hash() != hash {
                                return Err(anyhow!("Both genesis committee and genesis hash were specified, but the hashes do not match"));
                            }
                        }
                        (Some(genesis.clone()), 0, 0, genesis.hash())
                    }
                    (0, None) => {
                        return Err(anyhow!("At least one of genesis_committee or genesis_hash must be specified in config"));
                    }
                    _ => {
                        return Err(anyhow!(
                            "genesis committee must have length 0 or 1, not {}",
                            config.consensus.genesis_committee.len()
                        ));
                    }
                },
            };

        let (start_view, high_qc) = {
            match db.get_high_qc()? {
                Some(qc) => {
                    let high_block = block_store
                        .get_block(qc.block_hash)?
                        .ok_or_else(|| anyhow!("missing block that high QC points to!"))?;

                    let start_view = high_block.view() + 1;
                    info!("During recovery, starting consensus at view {}", start_view);
                    (start_view, qc)
                }
                None => {
                    let start_view = 1;
                    (start_view, QuorumCertificate::genesis(1024))
                }
            }
        };

        let mut consensus = Consensus {
            secret_key,
            config,
            block_store,
            message_sender,
            votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            high_qc,
            view: View::new(start_view),
            finalized_view: start_view.saturating_sub(1),
            pending_peers: Vec::new(),
            new_transactions: BTreeMap::new(),
            state,
            db,
            new_transactions_priority: BTreeMap::new(),
            // Seed the rng with the node's public key
            rng: <SmallRng as rand_core::SeedableRng>::seed_from_u64(u64::from_be_bytes(
                secret_key.node_public_key().as_bytes()[..8]
                    .try_into()
                    .unwrap(),
            )),
        };

        // If we're at genesis, add the genesis block.
        if latest_block_view == 0 {
            if let Some(genesis) = latest_block {
                consensus.add_block(genesis.clone())?;
            }
            consensus.save_highest_view(
                latest_block_hash,
                latest_block_view,
                latest_block_number,
            )?;
            // treat genesis as finalized
            consensus.finalize(latest_block_hash, latest_block_view)?;
        }

        Ok(consensus)
    }

    pub fn public_key(&self) -> NodePublicKey {
        self.secret_key.node_public_key()
    }

    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        public_key: NodePublicKey,
    ) -> Result<Option<(Option<PeerId>, ExternalMessage)>> {
        trace!(%peer_id, "adding peer to consensus");
        if self.pending_peers.contains(&Validator {
            peer_id,
            public_key,
            weight: 100,
        }) {
            return Ok(None);
        }

        self.pending_peers.push(Validator {
            peer_id,
            public_key,
            weight: 100,
        });

        debug!(%peer_id, "added pending peer");

        if self.view.get_view() == 1 {
            let Some(genesis) = self.get_block_by_view(0)? else {
                // if we don't have genesis that means we only have its hash
                // ergo we weren't, and can't be, part of the network at genesis and
                // can't vote for it anyway
                return Ok(None);
            };
            // If we're in the genesis committee, vote again.
            if genesis
                .committee
                .iter()
                .any(|v| v.peer_id == self.peer_id())
            {
                trace!("voting for genesis block");
                let leader = genesis.committee.leader(self.view.get_view());
                let vote = self.vote_from_block(&genesis);
                return Ok(Some((Some(leader.peer_id), ExternalMessage::Vote(vote))));
            }
        }

        Ok(None)
    }

    pub fn head_block(&self) -> Block {
        let highest_block_number = self.db.get_highest_block_number().unwrap().unwrap();

        trace!(
            "head block request: highest block number: {}",
            highest_block_number
        );

        self.block_store
            .get_block_by_number(highest_block_number)
            .unwrap()
            .unwrap()
    }

    /// This function is called when we suspect that we are out of sync with the network/need to catchup.
    /// We ask peers for their chain above our head, if the network is syncronised there should be nothing
    /// to return.
    pub fn download_blocks_up_to_head(&mut self) -> Result<()> {
        let head_block = self.head_block();

        let random_peer = self.get_random_other_peer();
        self.block_store
            .request_blocks(random_peer, head_block.header.number + 1)?;

        Ok(())
    }

    pub fn get_random_other_peer(&mut self) -> Option<PeerId> {
        let our_id = self.peer_id();
        self.head_block()
            .committee
            .iter()
            .filter(|v| v.peer_id != our_id)
            .choose(&mut self.rng)
            .map(|v| v.peer_id)
    }

    pub fn timeout(&mut self) -> Result<Option<(PeerId, ExternalMessage)>> {
        // We never want to timeout while on view 1
        if self.view.get_view() == 1 {
            let genesis = self
                .get_block_by_view(0)
                .unwrap()
                .ok_or_else(|| anyhow!("missing block"))?;
            // If we're in the genesis committee, vote again.
            if genesis
                .committee
                .iter()
                .any(|v| v.peer_id == self.peer_id())
            {
                info!("timeout in view 1, we will vote for genesis block rather than incrementing view");
                let leader = genesis.committee.leader(self.view.get_view());
                let vote = self.vote_from_block(&genesis);
                return Ok(Some((leader.peer_id, ExternalMessage::Vote(vote))));
            } else {
                info!("We are on view 1 but we are not a validator, so we are waiting.");
                let _ = self.download_blocks_up_to_head();
            }

            return Ok(None);
        }

        // Now consider whether we want to timeout - the timeout duration doubles every time, so it
        // Should eventually have all nodes on the same view
        let consensus_timeout_ms = self.config.consensus.consensus_timeout.as_millis() as u64;
        let head_block = self.head_block();
        let head_block_view = head_block.view();
        let time_since_last_view_change = SystemTime::now()
            .duration_since(self.view.last_timeout())
            .expect("last timeout seems to be in the future...")
            .as_millis() as u64;
        let view_difference = self.view.get_view().saturating_sub(head_block_view);
        let exponential_backoff_timeout = consensus_timeout_ms * 2u64.pow(view_difference as u32);
        let next_exponential_backoff_timeout =
            consensus_timeout_ms * 2u64.pow((view_difference + 1) as u32);

        if time_since_last_view_change < exponential_backoff_timeout {
            trace!(
                "Not proceeding with view change. Current view: {} - time since last: {}, timeout requires: {}",
                self.view.get_view(),
                time_since_last_view_change,
                exponential_backoff_timeout
            );
            return Ok(None);
        }

        trace!("Considering view change: view: {} time since: {} timeout: {} last known view: {} last hash: {}", self.view.get_view(), time_since_last_view_change, exponential_backoff_timeout, head_block_view, head_block.hash());

        info!(
            "***** TIMEOUT: View is now {} -> {}. Next view change in {}ms",
            self.view.get_view(),
            self.view.get_view() + 1,
            next_exponential_backoff_timeout
        );

        let _ = self.download_blocks_up_to_head();
        self.view.set_view(self.view.get_view() + 1);

        let leader = self
            .get_block(&self.high_qc.block_hash)?
            .ok_or_else(|| {
                anyhow!("missing block corresponding to our high qc - this should never happen")
            })?
            .committee
            .leader(self.view.get_view())
            .peer_id;

        let new_view = NewView::new(
            self.secret_key,
            self.high_qc.clone(),
            self.view.get_view(),
            self.secret_key.node_public_key(),
        );

        Ok(Some((leader, ExternalMessage::NewView(Box::new(new_view)))))
    }

    pub fn peer_id(&self) -> PeerId {
        self.secret_key.to_libp2p_keypair().public().to_peer_id()
    }

    pub fn proposal(
        &mut self,
        proposal: Proposal,
        during_sync: bool,
    ) -> Result<Option<(PeerId, Vote)>> {
        self.cleanup_memory();
        let (block, transactions) = proposal.into_parts();
        let head_block = self.head_block();

        trace!(
            block_view = block.view(),
            block_number = block.number(),
            "handling block proposal {}",
            block.hash()
        );

        if self.block_store.contains_block(block.hash())? {
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

        match self.check_block(&block) {
            Ok(()) => {}
            Err(e) => {
                if let Some(e) = e.downcast_ref::<MissingBlockError>() {
                    info!(?e, "missing block when checking block proposal - try and request the parent from the network: {}", block.header.number.saturating_sub(1));

                    let random_peer = self.get_random_other_peer();
                    self.block_store
                        .request_blocks(random_peer, block.header.number.saturating_sub(1))?;
                    return Ok(None);
                } else {
                    warn!(?e, "invalid block proposal received!");
                    return Ok(None);
                }
            }
        }

        self.update_high_qc_and_view(block.agg.is_some(), block.qc.clone())?;

        let proposal_view = block.view();
        let parent = self
            .get_block(&block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block parent"))?;
        let block_state_root = block.state_root_hash();

        trace!("checking if block view {} is safe", block.view());

        // If the proposed block is safe, vote for it and advance to the next round.
        if self.check_safe_block(&block, during_sync)? {
            trace!(
                "block view {} number {} aka {} is safe",
                block.view(),
                block.number(),
                block.hash()
            );

            let mut block_receipts: Vec<TransactionReceipt> = Vec::new();

            if head_block.hash() != parent.hash() || block.number() != head_block.header.number + 1
            {
                warn!(
                    "******* Fork detected! \nHead block: {} \nBlock prop: {}",
                    head_block, block
                );
                self.deal_with_fork(&block)?;
            }

            // Must make sure state root hash is set to the parent's state root hash before applying transactions
            if self.state.root_hash()? != parent.state_root_hash() {
                warn!("state root hash prior to block execution mismatch, expected: {:?}, actual: {:?}.\nHead: {}", parent.state_root_hash(), self.state.root_hash()?, head_block);
            }

            if !transactions.is_empty() {
                trace!("applying {} transactions to state", transactions.len());
            }

            for txn in &transactions {
                let txn = self.new_transaction(txn.clone())?;
                let tx_hash = txn.hash;
                if let Some(result) = self.apply_transaction(txn.clone(), parent.header)? {
                    self.db
                        .insert_block_hash_reverse_index(&tx_hash, &block.hash())?;
                    let receipt = TransactionReceipt {
                        block_hash: block.hash(),
                        tx_hash,
                        success: result.success,
                        contract_address: result.contract_address,
                        logs: result.logs,
                        gas_used: result.gas_used,
                    };
                    info!(?receipt, "applied transaction {:?}", receipt);
                    block_receipts.push(receipt);
                } else {
                    warn!("Failed to apply TX! Something might be wrong");
                }
            }

            // If we were the proposer we would've already processed the transactions
            if !self.db.contains_transaction_receipt(&block.hash())? {
                self.db
                    .insert_transaction_receipt(&block.hash(), &block_receipts)?;
            }

            // Important - only add blocks we are going to execute because they can potentially
            // overwrite the mapping of block height to block, which there should only be one of.
            // for example, this HAS to be after the deal with fork call
            self.add_block(block.clone())?;

            if self.state.root_hash()? != block_state_root {
                warn!(
                    "State root hash mismatch! Our state hash: {}, block hash: {:?} block prop: {}",
                    self.state.root_hash()?,
                    block_state_root,
                    block
                );
                return Err(anyhow!(
                    "state root hash mismatch, expected: {:?}, actual: {:?}",
                    block_state_root,
                    self.state.root_hash()
                ));
            }

            if self.view.get_view() != proposal_view + 1 {
                self.view.set_view(proposal_view + 1);

                debug!(
                    "*** setting view to proposal view... view is now {}",
                    self.view.get_view()
                );
            }

            self.save_highest_view(block.hash(), block.number(), proposal_view)?;

            if !block.committee.iter().any(|v| v.peer_id == self.peer_id()) {
                trace!(
                    "can't vote for block proposal, we aren't in the committee of length {:?}",
                    block.committee.len()
                );
                return Ok(None);
            } else {
                let vote = self.vote_from_block(&block);
                let next_leader = block.committee.leader(self.view.get_view()).peer_id;

                if !during_sync {
                    trace!(proposal_view, ?next_leader, "voting for block");
                    return Ok(Some((next_leader, vote)));
                }
            }
        } else {
            trace!("block is not safe");
        }

        Ok(None)
    }

    pub fn remove_tx_from_mempool(&mut self, tx_hash: &Hash) {
        let removed = match self.new_transactions.remove(tx_hash) {
            Some(tx) => tx,
            None => {
                return;
            }
        };

        // loop over priority txs and remove the tx (this shold be O(log n) as it will almost cert
        // be a leaf node)
        if let Some(priority_txs) = self.new_transactions_priority.get_mut(&removed.signer) {
            priority_txs.retain(|tx| tx.hash != *tx_hash);
        }

        // Finally, insert tx into the db, so there is no discontinuity where the TX can't
        // be found anywhere
        let _ = self.db.insert_transaction(tx_hash, &removed.tx);
    }

    pub fn apply_transaction(
        &mut self,
        txn: VerifiedTransaction,
        current_block: BlockHeader,
    ) -> Result<Option<TransactionApplyResult>> {
        let hash = txn.hash;

        // If we have the transaction in the mempool, remove it.
        self.remove_tx_from_mempool(&hash);

        let mut listener = TouchedAddressEventListener::default();

        let result = evm_ds::evm::tracing::using(&mut listener, || {
            self.state.apply_transaction(
                txn.clone(),
                self.config.eth_chain_id,
                current_block,
                false,
            )
        })?;

        for address in listener.touched {
            self.db.add_touched_address(address, hash)?;
        }

        if !result.success {
            info!("Transaction was a failure...");
        }

        Ok(Some(result))
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.db.get_touched_address_index(address)
    }

    // Get valid TXs to execute while also cleaning the mempool of TXs that are invalid
    // to do this, we refer to a binary heap which for each from address, contains a list of TXs
    // prioritised by nonce (so popping gives lowest), then by gas price and gas limit (highest)
    pub fn get_txns_to_execute(&mut self) -> Vec<VerifiedTransaction> {
        let mut ret = Vec::new();

        if self.config.consensus.block_tx_limit < 1 {
            warn!("Block TX limit is set to 0, no TXs will be added to the block");
        }

        // Loop over the prioritised txs, putting them in so long as they are valid
        for (from_addr, txs) in self.new_transactions_priority.iter_mut() {
            // get the nonce of the account, or zero if none
            let mut iter_nonce = self.state.must_get_account(*from_addr).nonce;
            let mut remove_all_txs = false;

            // Clear all nonces from the priority queue that are too low
            while let Some(txn) = txs.pop() {
                if txn.nonce < iter_nonce {
                    trace!(
                        "TX nonce {} too low, iter nonce {}, will be removed",
                        txn.nonce,
                        iter_nonce
                    );
                    continue;
                } else {
                    txs.push(txn);
                    break;
                }
            }

            // Push as many txs as have a sequential nonce into the map
            // We have to pop, as iterating over a binary heap is not in order.
            // So we put it all back afterward
            let mut temp_vec = Vec::new();
            while let Some(mut txn) = txs.pop() {
                txn.retries += 1;
                temp_vec.push(txn.clone());

                // if we have reached the block limit, break
                if ret.len() >= self.config.consensus.block_tx_limit {
                    break;
                }

                // if it is less than the iter nonce, we can skip it
                // this just means there are 'priority txs' with the same nonce but different fees
                if txn.nonce < iter_nonce {
                    trace!("lower priority tx ignored {} vs {}", txn.nonce, iter_nonce);
                    continue;
                }

                // If the nonce is too high, we will take another pass
                if txn.nonce > iter_nonce {
                    trace!(
                        "TX nonce {} too high, iter nonce {}, retry {} of {}",
                        txn.nonce,
                        iter_nonce,
                        txn.retries,
                        self.config.tx_retries
                    );

                    if txn.retries >= self.config.tx_retries {
                        warn!(?txn, "Tranaction has exceeded retries and all pending from this account will been removed");
                        remove_all_txs = true;
                        temp_vec.pop();
                    }

                    // all other TXs will have a higher nonce, so we can break
                    break;
                }

                // tx nonce == iter nonce, so we can add it
                match self.new_transactions.get(&txn.hash) {
                    Some(tx) => {
                        trace!("Adding tx to execute: {:?}", tx);
                        ret.push(tx.clone());
                        iter_nonce += 1;
                    }
                    None => {
                        warn!(
                            "Transaction {} not found in mempool, but was in priority txs",
                            txn.hash
                        );
                        temp_vec.pop();
                    }
                }
            }

            // If we need to remove the txs (retries timed out), remove it from the new_transactions and delete the entry
            // in the priority map
            if remove_all_txs {
                trace!("removing txs for from address {}", from_addr);
                while let Some(tx) = txs.pop() {
                    self.new_transactions.remove(&tx.hash);
                }
            }

            // Put the txs back in the heap
            txs.extend(temp_vec.into_iter());
        }

        // As cleanup, remove any `From` where the heap is empty
        self.new_transactions_priority
            .retain(|_, binary_heap| !binary_heap.is_empty());

        if !ret.is_empty() {
            trace!("Added {} priority txs to block", ret.len());
        }

        ret
    }

    /// Clear up anything in memory that is no longer required. This is to avoid memory leaks.
    pub fn cleanup_memory(&mut self) {
        // Wrt votes, we only care about votes on hashes for the current view or higher
        let keys_to_process: Vec<_> = self.votes.iter().map(|(k, _)| k.clone()).collect();

        for key in keys_to_process {
            if let Ok(Some(block)) = self.get_block(&key) {
                if block.view() < self.view.get_view() {
                    self.votes.remove(&key);
                }
            } else {
                warn!("Missing block for vote (this shouldn't happen), removing from memory");
                self.votes.remove(&key);
            }
        }

        // Wrt new views, we only care about new views for the current view or higher
        self.new_views
            .retain(|k, _| *k >= self.view.get_view());
    }

    pub fn vote(&mut self, vote: Vote) -> Result<Option<(Block, Vec<SignedTransaction>)>> {
        let Some(block) = self.get_block(&vote.block_hash)? else {
            return Ok(None);
        }; // TODO: Is this the right response when we recieve a vote for a block we don't know about?
        let block_hash = block.hash();
        let block_view = block.view();
        let current_view = self.view.get_view();
        trace!(block_view, current_view, %block_hash, "handling vote");

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
        // if the vote is too old and does not count anymore
        if block_view + 1 < self.view.get_view() {
            trace!("vote is too old");
            return Ok(None);
        }

        // verify the sender's signature on block_hash
        let (index, sender) = block
            .committee
            .iter()
            .enumerate()
            .find(|(_, v)| v.public_key == vote.public_key)
            .unwrap();
        vote.verify()?;

        let committee_size = block.committee.len();
        let (mut signatures, mut cosigned, mut cosigned_weight, mut supermajority_reached) =
            self.votes.get(&block_hash).cloned().unwrap_or_else(|| {
                (
                    Vec::new(),
                    bitvec![u8, bitvec::order::Msb0; 0; committee_size],
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
            cosigned_weight += sender.weight;

            supermajority_reached = cosigned_weight * 3 > block.committee.total_weight() * 2;
            let current_view = self.view.get_view();
            trace!(
                cosigned_weight,
                supermajority_reached,
                total_weight = block.committee.total_weight(),
                current_view,
                vote_view = block_view + 1,
                "storing vote"
            );
            if supermajority_reached {
                // if we are already in the round in which the vote counts and have reached supermajority
                if block_view + 1 == self.view.get_view() {
                    let qc =
                        self.qc_from_bits(block_hash, &signatures, cosigned.clone(), vote.view);
                    let parent_hash = qc.block_hash;
                    let parent = self
                        .get_block(&parent_hash)?
                        .ok_or_else(|| anyhow!("missing block"))?;
                    let parent_header = parent.header;

                    let previous_state_root_hash = self.state.root_hash()?;

                    if previous_state_root_hash != parent.state_root_hash() {
                        warn!("when proposing, state root hash mismatch, expected: {:?}, actual: {:?}", parent.state_root_hash(), previous_state_root_hash);
                        self.state.set_to_root(H256(parent.state_root_hash().0));
                    }

                    let transactions = self.get_txns_to_execute();

                    let applied_transactions: Vec<_> = transactions
                        .into_iter()
                        .filter_map(|tx| {
                            let result = self.apply_transaction(tx.clone(), parent_header);
                            result.transpose().map(|r| r.map(|_| tx.tx.clone()))
                        })
                        .collect::<Result<_>>()?;
                    let applied_transaction_hashes: Vec<_> = applied_transactions
                        .iter()
                        .map(|tx| tx.calculate_hash())
                        .collect();

                    let proposal = Block::from_qc(
                        self.secret_key,
                        self.view.get_view(),
                        parent.header.number + 1,
                        qc,
                        parent_hash,
                        self.state.root_hash()?,
                        applied_transaction_hashes,
                        SystemTime::max(SystemTime::now(), parent_header.timestamp),
                        self.get_next_committee(parent.committee),
                    );

                    self.state.set_to_root(H256(previous_state_root_hash.0));

                    self.votes.insert(
                        block_hash,
                        (signatures, cosigned, cosigned_weight, supermajority_reached),
                    );
                    // as a future improvement, process the proposal before broadcasting it
                    trace!(proposal_hash = ?proposal.hash(), ?proposal.header.view, ?proposal.header.number, "######### vote successful, we are proposing block");

                    return Ok(Some((proposal, applied_transactions)));
                    // we don't want to keep the collected votes if we proposed a new block
                    // we should remove the collected votes if we couldn't reach supermajority within the view
                }
            }
        }

        self.votes.insert(
            block_hash,
            (signatures, cosigned, cosigned_weight, supermajority_reached),
        );

        Ok(None)
    }

    fn get_next_committee(&mut self, mut committee: Committee) -> Committee {
        if committee.is_empty() {
            panic!("committee is empty, this should never happen");
        }

        if !self.pending_peers.is_empty() {
            info!(
                "*** adding {} pending peers to committee",
                self.pending_peers.len()
            );
        }

        committee.add_validators(self.pending_peers.drain(..));

        if committee.len() <= 1 {
            warn!(
                "committee is too small {}, something might be wrong",
                committee.len()
            );
        }

        committee
    }

    fn are_we_leader_for_view(&mut self, parent_hash: Hash, view: u64) -> bool {
        match self.leader_for_view(parent_hash, view) {
            Some(leader) => leader == self.peer_id(),
            None => false,
        }
    }

    fn leader_for_view(&mut self, parent_hash: Hash, view: u64) -> Option<PeerId> {
        let parent = self.get_block(&parent_hash);

        let parent = match parent {
            Ok(Some(parent)) => parent,
            _ => {
                warn!(
                    "parent not found while determining leader for view {}",
                    view
                );
                return None;
            }
        };

        Some(parent.committee.leader(view).peer_id)
    }

    fn committee_for_hash(&mut self, parent_hash: Hash) -> Result<Committee> {
        let parent = self.get_block(&parent_hash);

        let parent = match parent {
            Ok(Some(parent)) => parent,
            _ => {
                warn!("parent not found during committee_for_hash");
                return Err(anyhow!("parent not found during committee_for_hash"));
            }
        };

        Ok(parent.committee)
    }

    pub fn new_view(&mut self, _: PeerId, new_view: NewView) -> Result<Option<Block>> {
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
        let committee = self.committee_for_hash(new_view.qc.block_hash)?;
        // verify the sender's signature on the block hash
        let Some((index, sender)) = committee
            .iter()
            .enumerate()
            .find(|(_, v)| v.public_key == new_view.public_key)
        else {
            debug!("ignoring new view from unknown node (buffer?) - committee size is : {:?} hash is: {:?} high hash is: {:?}", committee.len(), new_view.qc.block_hash, self.high_qc.block_hash);
            return Ok(None);
        };
        new_view.verify(sender.public_key)?;

        // check if the sender's qc is higher than our high_qc or even higher than our view
        self.update_high_qc_and_view(false, new_view.qc.clone())?;

        let committee_size = committee.len();

        let NewViewVote {
            mut signatures,
            mut signers,
            mut cosigned,
            mut cosigned_weight,
            mut qcs,
        } = self
            .new_views
            .remove(&new_view.view)
            .unwrap_or_else(|| NewViewVote {
                signatures: Vec::new(),
                signers: Vec::new(),
                cosigned: bitvec![u8, bitvec::order::Msb0; 0; committee_size],
                cosigned_weight: 0,
                qcs: Vec::new(),
            });

        let mut supermajority = false;

        // the index is not checked here...
        // if the vote is new, store it
        if !cosigned[index] {
            signatures.push(new_view.signature);
            signers.push(index as u16);
            cosigned.set(index, true);
            cosigned_weight += sender.weight;
            qcs.push(new_view.qc);

            supermajority = cosigned_weight * 3 > committee.total_weight() * 2;

            let num_signers = signers.len();
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

                // if we are already in the round in which the vote counts and have reached supermajority
                if new_view.view == self.view.get_view() {
                    // todo: the aggregate qc is an aggregated signature on the qcs, view and validator index which can be batch verified
                    let agg =
                        self.aggregate_qc_from_indexes(new_view.view, qcs, &signatures, signers)?;
                    let high_qc = self.get_highest_from_agg(&agg)?;
                    let parent_hash = high_qc.block_hash;
                    let parent = self
                        .get_block(&parent_hash)?
                        .ok_or_else(|| anyhow!("missing block"))?;
                    let state_root_hash = parent.state_root_hash();

                    // why does this have no txn?
                    let proposal = Block::from_agg(
                        self.secret_key,
                        self.view.get_view(),
                        parent.header.number + 1,
                        high_qc.clone(),
                        agg,
                        parent_hash,
                        state_root_hash,
                        SystemTime::max(SystemTime::now(), parent.timestamp()),
                        self.get_next_committee(parent.committee),
                    );

                    trace!("Our high QC is {:?}", self.high_qc);

                    trace!(proposal_hash = ?proposal.hash(), view = self.view.get_view(), height = proposal.header.number, "######### creating proposal block from new view");

                    // as a future improvement, process the proposal before broadcasting it
                    return Ok(Some(proposal));
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
                    signers,
                    cosigned,
                    cosigned_weight,
                    qcs,
                },
            );
        }

        Ok(None)
    }

    pub fn new_transaction(&mut self, txn: SignedTransaction) -> Result<VerifiedTransaction> {
        let txn = txn.verify()?;
        // If we already have the tx, ignore it
        if self.new_transactions.contains_key(&txn.hash) {
            return Ok(txn);
        }

        let txn_order = TxnOrder::new(txn.hash, &txn.tx);

        self.new_transactions_priority
            .entry(txn.signer)
            .or_default()
            .push(txn_order);

        self.new_transactions.insert(txn.hash, txn.clone());

        Ok(txn)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<VerifiedTransaction>> {
        if let Some(txn) = self.new_transactions.get(&hash) {
            return Ok(Some(txn.clone()));
        }

        self.db
            .get_transaction(&hash)?
            .map(|tx| tx.verify())
            .transpose()
    }

    pub fn get_transaction_receipt(&self, hash: &Hash) -> Result<Option<TransactionReceipt>> {
        let Some(block_hash) = self.db.get_block_hash_reverse_index(hash)? else {
            return Ok(None);
        };
        let block_receipts = self
            .db
            .get_transaction_receipt(&block_hash)?
            .unwrap_or_default();
        Ok(block_receipts
            .into_iter()
            .find(|receipt| receipt.tx_hash == *hash))
    }

    pub fn get_logs_in_block(
        &self,
        hash: Hash,
        event: Event,
        emitter: Address,
    ) -> Result<Vec<Log>> {
        let receipts = self.db.get_transaction_receipt(&hash)?.unwrap_or_default();

        let logs: Result<Vec<_>, _> = receipts
            .into_iter()
            .flat_map(|receipt| receipt.logs)
            .filter(|log| log.address == emitter && log.topics[0] == event.signature())
            .map(|log| {
                event.parse_log_whole(RawLog {
                    topics: log.topics,
                    data: log.data,
                })
            })
            .collect();

        Ok(logs?)
    }

    fn save_highest_view(&mut self, block_hash: Hash, number: u64, view: u64) -> Result<()> {
        self.block_store.set_canonical(number, view, block_hash)?;
        self.db.put_highest_block_number(number)?;
        Ok(())
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
            self.db.set_high_qc(new_high_qc.clone())?;
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
                self.db.set_high_qc(new_high_qc.clone())?;
                self.high_qc = new_high_qc;
                self.view.set_view(new_high_qc_block_view + 1);
            }
        }

        Ok(())
    }

    fn aggregate_qc_from_indexes(
        &self,
        view: u64,
        qcs: Vec<QuorumCertificate>,
        signatures: &[NodeSignature],
        signers: Vec<u16>,
    ) -> Result<AggregateQc> {
        assert_eq!(qcs.len(), signatures.len());
        assert_eq!(signatures.len(), signers.len());
        Ok(AggregateQc {
            signature: NodeSignature::aggregate(signatures)?,
            signers,
            view,
            qcs,
        })
    }

    fn qc_from_bits(
        &self,
        block_hash: Hash,
        signatures: &[NodeSignature],
        cosigned: BitVec,
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
        let Some(qc_block) = self.get_block(&proposal.qc.block_hash)? else {
            trace!("could not get qc for block: {}", proposal.qc.block_hash);
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

    fn check_and_commit(&mut self, proposal: &Block) -> Result<()> {
        // The condition for a block to be finalized is if there is a direct two-chain. From the paper:
        // Once a replica is convinced, it checks
        // if a two-chain is formed over the top of the parent of the
        // block pointed by the highQC (the first chain in the two-chain
        // formed has to be a one-direct chain in case of pipelined Fast-
        // HotStuff). Then a replica can safely commit the parent of the
        // block pointed by the highQC.
        // So, in short, look up parent of QC, and finalize it iff the two subsequent blocks
        // have views N+1, N+2 (the final one being proposal block).

        let Some(qc_block) = self.get_block(&proposal.qc.block_hash)? else {
            warn!("missing qc block when checking whether to finalize!");
            return Err(MissingBlockError::from(proposal.qc.block_hash).into());
        };

        // At genesis it could be fine not to have a qc block, so don't error.
        let Some(qc_parent) = self.get_block(&qc_block.parent_hash())? else {
            warn!("missing qc parent block when checking whether to finalize!");
            return Ok(());
        };

        // Likewise, block + 1 doesn't have to exist neccessarily
        let Some(qc_child) = self.get_block_by_number(qc_parent.number() + 1)? else {
            warn!("missing qc child when checking whether to finalize!");
            return Ok(());
        };

        if qc_parent.view() + 1 == qc_child.view() && qc_parent.view() + 2 == proposal.view() {
            self.finalize(qc_parent.hash(), qc_parent.view())?;
        } else {
            warn!(
                "Failed to finalize block! Not finalizing QC block {} with view {} and number {}",
                qc_block.hash(),
                qc_block.view(),
                qc_block.number()
            );
        }

        Ok(())
    }

    /// Intended to be used with the oldest pending block, to move the
    /// finalized tip forward by one. Does not update view/height.
    pub fn finalize(&mut self, hash: Hash, view: u64) -> Result<()> {
        self.finalized_view = view;
        self.db.put_latest_finalized_view(view)?;

        if self.config.consensus.is_main {
            // Check for new shards to join
            let shard_logs = self.get_logs_in_block(
                hash,
                contracts::shard_registry::SHARD_ADDED_EVT.clone(),
                contract_addr::SHARD_CONTRACT,
            )?;
            for log in shard_logs {
                let Some(shard_id) = log
                    .params
                    .into_iter()
                    .find(|param| param.name == "id")
                    .and_then(|param| param.value.into_uint())
                else {
                    return Err(anyhow!("LaunchShard event does not contain an id!"));
                };
                self.message_sender
                    .send_message_to_coordinator(InternalMessage::LaunchShard(shard_id.as_u64()))?;
            }
        }

        Ok(())
    }

    /// Check the validity of a block
    fn check_block(&mut self, block: &Block) -> Result<()> {
        block.verify_hash()?;

        // This should be checked against genesis
        if block.view() == 0 {
            return Ok(());
        }

        let Some(finalized_block) = self.get_block_by_view(self.finalized_view)? else {
            return Err(MissingBlockError::from(self.finalized_view).into());
        };
        if block.view() < finalized_block.view() {
            return Err(anyhow!(
                "block is too old: view is {} but we have finalized {}",
                block.view(),
                finalized_block.view()
            ));
        }

        let Some(parent) = self.get_block(&block.parent_hash())? else {
            warn!(
                "Missing parent block while trying to check validity of block {}",
                block.number()
            );
            return Err(MissingBlockError::from(block.parent_hash()).into());
        };

        // Derive the proposer from the block's view
        let proposer = parent.committee.leader(block.view());

        trace!(
            "(check block) I think the block proposer is: {}, we are {}",
            proposer.peer_id,
            self.peer_id()
        );
        // Verify the proposer's signature on the block
        let verified = proposer
            .public_key
            .verify(block.hash().as_bytes(), block.signature());

        if verified.is_err() {
            return Err(anyhow!("invalid block signature found! block hash: {:?} block view: {:?} committee len {:?}", block.hash(), block.view(), parent.committee.len()));
        }

        // Check if the co-signers of the block's QC represent the supermajority.
        self.check_quorum_in_bits(&block.qc.cosigned, &parent.committee)?;
        // Verify the block's QC signature - note the parent should be the committee the QC
        // was signed over.
        self.verify_qc_signature(&block.qc, parent.committee.public_keys())?;
        if let Some(agg) = &block.agg {
            // Check if the signers of the block's aggregate QC represent the supermajority
            self.check_quorum_in_indices(&agg.signers, &parent.committee)?;
            // Verify the aggregate QC's signature
            self.batch_verify_agg_signature(agg, &parent.committee)?;
        }

        // Retrieve the highest among the aggregated QCs and check if it equals the block's QC.
        let block_high_qc = self.get_high_qc_from_block(block)?;
        let Some(block_high_qc_block) = self.get_block(&block_high_qc.block_hash)? else {
            warn!("missing finalized block4");
            return Err(MissingBlockError::from(block_high_qc.block_hash).into());
        };
        // Prevent the creation of forks from the already committed chain
        if block_high_qc_block.view() < finalized_block.view() {
            warn!(
                "invalid block - high QC view is {} while finalized is {}. Our High QC: {}, block: {:?}",
                block_high_qc_block.view(),
                finalized_block.view(),
                self.high_qc,
                block);
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
        // Genesis is an exception for now since the timestamp can differ across nodes
        let difference = block
            .timestamp()
            .elapsed()
            .unwrap_or_else(|err| err.duration());
        if difference > self.config.allowed_timestamp_skew && parent.view() > 0 {
            warn!(
                "timestamp difference greater than allowed skew: {difference:?}. Blocks {0:?} and {1:?}", block.view(), parent.view(),
            );
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

    // Checks for the validity of a block and adds it to our block store if valid.
    // Returns true when the block is valid and newly seen and false otherwise.
    pub fn receive_block(&mut self, proposal: Proposal) -> Result<bool> {
        let (block, transactions) = proposal.into_parts();
        trace!(
            "received block: {} number: {}, view: {}",
            block.hash(),
            block.number(),
            block.view()
        );
        if self.block_store.contains_block(block.hash())? {
            trace!(
                "recieved block already seen: {} - our head is {}",
                block.hash(),
                self.head_block()
            );
            return Ok(false);
        }

        // Check whether it is loose or not - we do not store loose blocks.
        if !self.block_store.contains_block(block.parent_hash())? {
            trace!("received block is loose: {}", block.hash());

            warn!(
                "missing received block the parent! Lets request the parent, then: {}",
                block.parent_hash()
            );
            self.block_store
                .request_blocks(None, block.header.number.saturating_sub(1))?;
            return Ok(false);
        }

        match self.check_block(&block) {
            Ok(()) => {
                trace!(
                    "updating high QC and view, blocks seems good! hash: {} number: {} view: {}",
                    block.hash(),
                    block.number(),
                    block.view()
                );

                self.update_high_qc_and_view(block.agg.is_some(), block.qc.clone())?;

                let current_head = self.head_block();

                self.proposal(Proposal::from_parts(block, transactions), true)?;

                // Return whether the head block hash changed as to whether it was new
                Ok(self.head_block().hash() != current_head.hash())
            }
            Err(e) => {
                warn!(?e, "invalid block received during sync!");

                Ok(false)
            }
        }
    }

    fn add_block(&mut self, block: Block) -> Result<()> {
        let hash = block.hash();
        debug!(?hash, ?block.header.view, ?block.header.number, "added block");
        self.block_store.process_block(block)?;
        Ok(())
    }

    fn vote_from_block(&self, block: &Block) -> Vote {
        Vote::new(
            self.secret_key,
            block.hash(),
            self.secret_key.node_public_key(),
            block.view(),
        )
    }

    fn get_high_qc_from_block<'a>(&self, block: &'a Block) -> Result<&'a QuorumCertificate> {
        let Some(agg) = &block.agg else {
            return Ok(&block.qc);
        };

        let high_qc = self.get_highest_from_agg(agg)?;

        if &block.qc != high_qc {
            return Err(anyhow!("qc mismatch"));
        }

        Ok(&block.qc)
    }

    pub fn get_block(&self, key: &Hash) -> Result<Option<Block>> {
        self.block_store.get_block(*key)
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        self.block_store.get_block_by_view(view)
    }

    pub fn get_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        self.block_store.get_block_by_number(number)
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
            .get_block_by_number(number)?
            .map(|block| self.state.at_root(H256(block.state_root_hash().0))))
    }

    pub fn try_get_state_at(&self, number: u64) -> Result<State> {
        self.state_at(number)?
            .ok_or_else(|| anyhow!("No block at height {number}"))
    }

    pub fn seen_tx_already(&self, hash: &Hash) -> Result<bool> {
        Ok(self.new_transactions.contains_key(hash) || self.db.contains_transaction(hash)?)
    }

    fn get_highest_from_agg<'a>(&self, agg: &'a AggregateQc) -> Result<&'a QuorumCertificate> {
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
            .map(|(qc, _)| qc)
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

    fn batch_verify_agg_signature(&self, agg: &AggregateQc, committee: &Committee) -> Result<()> {
        let messages: Vec<_> = agg
            .qcs
            .iter()
            .enumerate()
            .map(|(i, qc)| {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(qc.compute_hash().as_bytes());
                bytes.extend_from_slice(&agg.signers[i].to_be_bytes());
                bytes.extend_from_slice(&agg.view.to_be_bytes());
                bytes
            })
            .collect();
        let _messages: Vec<_> = messages.iter().map(|m| m.as_slice()).collect();

        let _public_keys: Vec<_> = agg
            .signers
            .iter()
            .map(|i| committee.get_by_index(*i as usize).unwrap().public_key)
            .collect();

        // TODO: Implement batch verification - this will not work atm.
        //verify_messages(agg.signature, &messages, &public_keys)
        Ok(())
    }

    fn check_quorum_in_bits(&self, cosigned: &BitSlice, committee: &Committee) -> Result<()> {
        let cosigned_sum: u128 = committee
            .iter()
            .enumerate()
            .map(|(i, v)| if cosigned[i] { v.weight } else { 0 })
            .sum();

        if cosigned_sum * 3 <= committee.total_weight() * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    fn check_quorum_in_indices(&self, signers: &[u16], committee: &Committee) -> Result<()> {
        let signed_sum: u128 = signers
            .iter()
            .map(|i| committee.get_by_index(*i as usize).unwrap().weight)
            .sum();

        if signed_sum * 3 <= committee.total_weight() * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    /// Deal with the fork to this block. The block is assumed to be valid to switch to.
    /// This will make it so the block is ready to become the new head
    fn deal_with_fork(&mut self, block: &Block) -> Result<()> {
        // Start at the head block and recursively unwind the changes that have been made
        // until the head block is the parent of this block.
        while self.head_block().header.number >= block.header.number {
            let head_block = self.head_block();
            let parent_block = self
                .get_block(&head_block.parent_hash())?
                .ok_or_else(|| anyhow!("missing block parent when reverting blocks!"))?;

            if head_block.header.view == 0 {
                panic!("genesis block is not supposed to be reverted");
            }

            trace!("Reverting block {}", head_block);
            // block store doesn't require anything, it will just hold blocks that may now be invalid
            // block transactions need to be removed from self.transactions and re-injected
            for tx_hash in &head_block.transactions {
                let orig_tx = self.get_transaction_by_hash(*tx_hash).unwrap().unwrap();
                self.db.remove_transaction(tx_hash)?;

                // Put tx back in.
                self.new_transaction(orig_tx.tx).unwrap();

                // block hash reverse index, remove tx hash too
                self.db.remove_block_hash_reverse_index(tx_hash)?;
            }

            // TX receipts are indexed by block
            self.db.remove_transaction_receipt(&head_block.hash())?;

            // State is easily set - must be to the parent block, though
            trace!("Setting state to: {}", parent_block.state_root_hash());
            self.state
                .set_to_root(H256(parent_block.state_root_hash().0));

            // Persistence - only need to update head block pointer as it should be impossible
            // to change finalized height
            let new_highest = head_block.header.number.saturating_sub(1);
            self.db.put_highest_block_number(new_highest)?;

            // touched address index: TODO
        }

        Ok(())
    }
}
