use anyhow::{anyhow, Result};
use bitvec::bitvec;
use eth_trie::MemoryDB;
use libp2p::PeerId;
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    error::Error,
    fmt::Display,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, trace};

use crate::message::Message;
use crate::{
    block_store::BlockStore,
    cfg::Config,
    crypto::{verify_messages, Hash, NodePublicKey, NodeSignature, SecretKey},
    exec::TouchedAddressEventListener,
    exec::TransactionApplyResult,
    message::{
        AggregateQc, BitSlice, BitVec, Block, BlockHeader, BlockRef, NewView, Proposal,
        QuorumCertificate, Vote,
    },
    state::{Address, SignedTransaction, State, TransactionReceipt},
    time::SystemTime,
};

#[derive(Debug)]
struct NewViewVote {
    signatures: Vec<NodeSignature>,
    signers: Vec<u16>,
    cosigned: BitVec,
    cosigned_weight: u128,
    qcs: Vec<QuorumCertificate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Validator {
    pub public_key: NodePublicKey,
    pub peer_id: PeerId,
    pub weight: u128,
}

#[derive(Debug)]
struct MissingBlockError(BlockRef);

impl Display for MissingBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing block: {:?}", self.0)
    }
}

impl Error for MissingBlockError {}

#[derive(Debug)]
pub struct Consensus {
    secret_key: SecretKey,
    config: Config,
    block_store: BlockStore,
    votes: BTreeMap<Hash, (Vec<NodeSignature>, BitVec, u128, bool)>,
    new_views: BTreeMap<u64, NewViewVote>,
    high_qc: QuorumCertificate,
    view: u64,
    finalized_view: u64,
    /// Peers that have appeared between the last view and this one. They will be added to the committee before the next view.
    pending_peers: Vec<Validator>,
    /// Transactions that have been broadcasted by the network, but not yet executed. Transactions will be removed from this map once they are executed.
    new_transactions: BTreeMap<Hash, SignedTransaction>,
    /// Transactions that have been executed and included in a block, and the blocks the are
    /// included in.
    transactions: BTreeMap<Hash, SignedTransaction>,
    transaction_receipts: BTreeMap<Hash, TransactionReceipt>,
    /// The account store.
    state: State,
    /// An index of address to a list of transaction hashes, for which this address appeared somewhere in the
    /// transaction trace. The list of transations is ordered by execution order.
    touched_address_index: BTreeMap<Address, Vec<Hash>>,
    //buffered_vote: Option<Vote>,
    //buffered_proposal: Option<Proposal>,
}

impl Consensus {
    pub fn new(
        secret_key: SecretKey,
        config: Config,
        database: MemoryDB,
        message_sender: UnboundedSender<(Option<PeerId>, Message)>,
    ) -> Result<Self> {
        let mut consensus = Consensus {
            secret_key,
            config: config.clone(),
            block_store: BlockStore::new(message_sender),
            votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            high_qc: QuorumCertificate::genesis(),
            view: 1,
            finalized_view: 0,
            pending_peers: Vec::new(),
            new_transactions: BTreeMap::new(),
            transactions: BTreeMap::new(),
            transaction_receipts: BTreeMap::new(),
            state: State::new(Arc::new(database))?,
            touched_address_index: BTreeMap::new(),
        };

        let genesis_committee = config
            .genesis_committee
            .into_iter()
            .map(|(public_key, peer_id)| Validator {
                public_key,
                peer_id,
                weight: 100,
            })
            .collect();
        let genesis_state_root_hash = consensus.state.root_hash()?;
        consensus.add_block(Block::genesis(genesis_committee, genesis_state_root_hash));

        Ok(consensus)
    }

    fn committee(&self) -> Result<&[Validator]> {
        if let Ok(block) = self.get_block_by_view(self.view.saturating_sub(1)) {
            Ok(&block.committee)
        } else {
            Ok(&[])
        }
    }

    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        public_key: NodePublicKey,
    ) -> Result<Option<(Option<PeerId>, Message)>> {
        if self.pending_peers.contains(&Validator {
            peer_id,
            public_key,
            weight: 100,
        }) {
            return Ok(None);
        }

        if self
            .committee()?
            .iter()
            .filter(|v| v.peer_id == peer_id)
            .count()
            > 0
        {
            return Ok(None);
        }

        self.pending_peers.push(Validator {
            peer_id,
            public_key,
            weight: 100,
        });

        debug!(%peer_id, "added pending peer");

        if self.view == 1 {
            let me = self.secret_key.to_libp2p_keypair().public().to_peer_id();
            let genesis = self.get_block_by_view(0)?;
            // If we're in the genesis committee, vote again.
            // TODO: Make this work for genesis committee with multiple participants?
            if genesis.committee.iter().any(|v| v.peer_id == me) {
                trace!("voting for genesis block");
                let leader = self.get_leader(self.view)?;
                let vote = self.vote_from_block(genesis);
                return Ok(Some((Some(leader.peer_id), Message::Vote(vote))));
            }
        }

        Ok(None)
    }

    fn download_blocks_up_to(&mut self, to: u64) {
        for view in (self.view + 1)..to {
            self.view = view;
            self.block_store.request_block_by_view(view);
        }
        self.view = to + 1;
    }

    pub fn timeout(&mut self) -> Result<(PeerId, NewView)> {
        self.view += 1;

        let leader = self.get_leader(self.view)?.peer_id;
        let new_view = NewView::new(
            self.secret_key,
            self.high_qc.clone(),
            self.view,
            self.secret_key.node_public_key(),
        );
        Ok((leader, new_view))
    }

    pub fn proposal(&mut self, proposal: Proposal) -> Result<Option<(PeerId, Vote)>> {
        let (block, transactions) = proposal.into_parts();
        trace!(block_view = block.view(), "handling block proposal");

        if self.block_store.contains_block(block.hash()) {
            trace!("ignoring block proposal, block store contains this block already");
            return Ok(None);
        }

        match self.check_block(&block) {
            Ok(()) => {}
            Err(e) => {
                if let Some(e) = e.downcast_ref::<MissingBlockError>() {
                    trace!(?e, "missing block");
                    match e.0 {
                        BlockRef::Hash(hash) => self.block_store.request_block(hash),
                        BlockRef::View(view) => self.block_store.request_block_by_view(view),
                    }

                    self.add_block(block);

                    return Ok(None);
                } else {
                    return Err(e);
                }
            }
        }

        self.add_block(block.clone());
        self.update_high_qc_and_view(block.agg.is_some(), block.qc.clone())?;

        let proposal_view = block.view();
        let parent = self.get_block(&block.parent_hash())?;
        let parent_header = parent.header;
        let next_leader = block.committee[proposal_view as usize % block.committee.len()].peer_id;

        // If the proposed block is safe, vote for it and advance to the next round.
        trace!("checking whether block is safe");
        if self.check_safe_block(&block) {
            trace!("block is safe");

            for txn in &transactions {
                if let Some(result) = self.apply_transaction(txn.clone(), parent_header)? {
                    let receipt = TransactionReceipt {
                        block_hash: block.hash(),
                        success: result.success,
                        contract_address: result.contract_address,
                        logs: result.logs,
                    };
                    self.transaction_receipts.insert(txn.hash(), receipt);
                }
            }
            if self.state.root_hash()? != block.state_root_hash() {
                return Err(anyhow!(
                    "state root hash mismatch, expected: {:?}, actual: {:?}",
                    block.state_root_hash(),
                    self.state.root_hash()
                ));
            }
            self.download_blocks_up_to(proposal_view.saturating_sub(1));
            self.view = proposal_view + 1;

            if !block
                .committee
                .iter()
                .any(|v| v.peer_id == self.secret_key.to_libp2p_keypair().public().to_peer_id())
            {
                trace!("can't vote for block proposal, we aren't in the committee");
                Ok(None)
            } else {
                trace!(proposal_view, "voting for block");
                let vote = self.vote_from_block(&block);

                Ok(Some((next_leader, vote)))
            }
        } else {
            trace!("block is not safe");
            Ok(None)
        }
    }

    pub fn apply_transaction(
        &mut self,
        txn: SignedTransaction,
        current_block: BlockHeader,
    ) -> Result<Option<TransactionApplyResult>> {
        let hash = txn.hash();
        trace!(?hash, "executing transaction");

        // If we have the transaction in the mempool, remove it.
        self.new_transactions.remove(&hash);

        // Ensure the transaction has a valid signature
        txn.verify()?;

        // If we haven't applied the transaction yet, do so. This ensures we don't execute the transaction twice if we
        // already executed it in the process of proposing this block.
        if let Entry::Vacant(entry) = self.transactions.entry(hash) {
            let mut listener = TouchedAddressEventListener::default();
            let result = evm_ds::evm::tracing::using(&mut listener, || {
                self.state
                    .apply_transaction(txn.clone(), self.config.eth_chain_id, current_block)
            })?;
            trace!(?hash, "tranasction applied to state");

            entry.insert(txn);
            for address in listener.touched {
                self.touched_address_index
                    .entry(Address(address))
                    .or_default()
                    .push(hash);
            }
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    pub fn get_touched_transactions(&self, address: Address) -> Vec<Hash> {
        self.touched_address_index
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }

    pub fn vote(&mut self, vote: Vote) -> Result<Option<(Block, Vec<SignedTransaction>)>> {
        let Ok(block) = self.get_block(&vote.block_hash) else { return Ok(None); }; // TODO: Is this the right response when we recieve a vote for a block we don't know about?
        let block_hash = block.hash();
        let block_view = block.view();
        trace!(block_view, self.view, %block_hash, "handling vote");

        // if we are not the leader of the round in which the vote counts
        if block.committee[block_view as usize % block.committee.len()].public_key
            != self.secret_key.node_public_key()
        {
            trace!(vote_view = block_view + 1, "skipping vote, not the leader");
            return Ok(None);
        }
        // if the vote is too old and does not count anymore
        if block_view + 1 < self.view {
            trace!("vote is too old");
            return Ok(None);
        }

        // verify the sender's signature on block_hash
        let (index, &sender) = block // TODO: Is this the right committee?
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
            trace!("supermajority already reached in this round");
            return Ok(None);
        }

        let mut supermajority = false;
        // if the vote is new, store it
        if !cosigned[index] {
            signatures.push(vote.signature);
            cosigned.set(index, true);
            cosigned_weight += sender.weight;

            supermajority = cosigned_weight * 3 > self.committee_weight(&block.committee)? * 2;
            trace!(
                cosigned_weight,
                supermajority,
                self.view,
                vote_view = block_view + 1,
                "storing vote"
            );
            if supermajority {
                self.block_store.request_block_by_view(block_view);
                self.download_blocks_up_to(block_view);

                // if we are already in the round in which the vote counts and have reached supermajority
                if block_view + 1 == self.view {
                    let qc = self.qc_from_bits(block_hash, &signatures, cosigned.clone());
                    let parent_hash = qc.block_hash;
                    let parent = self.get_block(&parent_hash)?;
                    let parent_header = parent.header;

                    let applied_transactions: Vec<_> =
                        self.new_transactions.values().cloned().collect();
                    let applied_transactions: Vec<_> = applied_transactions
                        .into_iter()
                        .filter_map(|tx| {
                            let result = self.apply_transaction(tx.clone(), parent_header);
                            result.transpose().map(|r| {
                                r.map(|r| (tx.clone(), r.success, r.contract_address, r.logs))
                            })
                        })
                        .collect::<Result<_>>()?;
                    let applied_transaction_hashes: Vec<_> = applied_transactions
                        .iter()
                        .map(|(tx, _, _, _)| tx.hash())
                        .collect();

                    let proposal = Block::from_qc(
                        self.secret_key,
                        self.view,
                        qc,
                        parent_hash,
                        self.state.root_hash()?,
                        applied_transaction_hashes,
                        SystemTime::max(SystemTime::now(), parent_header.timestamp),
                        self.get_next_committee()?,
                    );

                    let applied_transactions: Vec<_> = applied_transactions
                        .into_iter()
                        .map(|(tx, success, contract_address, logs)| {
                            self.transactions.insert(tx.hash(), tx.clone());
                            let receipt = TransactionReceipt {
                                block_hash: proposal.hash(),
                                success,
                                contract_address,
                                logs,
                            };
                            self.transaction_receipts.insert(tx.hash(), receipt);
                            tx
                        })
                        .collect();

                    supermajority_reached = true;
                    self.votes.insert(
                        block_hash,
                        (signatures, cosigned, cosigned_weight, supermajority_reached),
                    );
                    // as a future improvement, process the proposal before broadcasting it
                    trace!(proposal_hash = ?proposal.hash(), "vote successful");
                    return Ok(Some((proposal, applied_transactions)));
                    // we don't want to keep the collected votes if we proposed a new block
                    // we should remove the collected votes if we couldn't reach supermajority within the view
                }
            }
        }
        if !supermajority {
            self.votes.insert(
                block_hash,
                (signatures, cosigned, cosigned_weight, supermajority_reached),
            );
        }

        Ok(None)
    }

    fn get_next_committee(&mut self) -> Result<Vec<Validator>> {
        let committee = self.committee()?.to_vec();
        let joiners = self
            .pending_peers
            .drain(..)
            .filter(|v1| !committee.iter().any(|v2| v1.peer_id == v2.peer_id));
        Ok(committee.iter().cloned().chain(joiners).collect())
    }

    pub fn new_view(&mut self, _: PeerId, new_view: NewView) -> Result<Option<Block>> {
        // if we are not the leader of the round in which the vote counts
        if self.get_leader(new_view.view)?.public_key != self.secret_key.node_public_key() {
            trace!(new_view.view, "skipping new view, not the leader");
            return Ok(None);
        }
        // if the vote is too old and does not count anymore
        if new_view.view < self.view {
            return Ok(None);
        }
        // verify the sender's signature on the block hash
        let Some((index, sender)) = self
            .committee()?
            .iter()
            .enumerate()
            .find(|(_, v)| v.public_key == new_view.public_key) else {
                debug!("ignoring new view from unknown node (buffer?)");
                return Ok(None);
            };
        let sender = *sender;
        new_view.verify(sender.public_key)?;

        // check if the sender's qc is higher than our high_qc or even higher than our view
        self.update_high_qc_and_view(false, new_view.qc.clone())?;

        let committee_size = self.committee()?.len();
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
        // if the vote is new, store it
        if !cosigned[index] {
            signatures.push(new_view.signature);
            signers.push(index as u16);
            cosigned.set(index, true);
            cosigned_weight += sender.weight;
            qcs.push(new_view.qc);
            // TODO: New views broken
            supermajority = cosigned_weight * 3 > self.committee_weight(&[])? * 2;
            let num_signers = signers.len();
            trace!(
                num_signers,
                cosigned_weight,
                supermajority,
                self.view,
                new_view.view,
                "storing vote for new view"
            );
            if supermajority {
                self.download_blocks_up_to(new_view.view - 1);

                // if we are already in the round in which the vote counts and have reached supermajority
                if new_view.view == self.view {
                    // todo: the aggregate qc is an aggregated signature on the qcs, view and validator index which can be batch verified
                    let agg =
                        self.aggregate_qc_from_indexes(new_view.view, qcs, &signatures, signers)?;
                    let high_qc = self.get_highest_from_agg(&agg)?;
                    let parent_hash = high_qc.block_hash;
                    let state_root_hash = self.state.root_hash()?;
                    let parent = self.get_block(&parent_hash)?;
                    let proposal = Block::from_agg(
                        self.secret_key,
                        self.view,
                        high_qc.clone(),
                        agg,
                        parent_hash,
                        state_root_hash,
                        SystemTime::max(SystemTime::now(), parent.timestamp()),
                        self.get_next_committee()?,
                    );
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

    pub fn new_transaction(&mut self, txn: SignedTransaction) -> Result<()> {
        txn.verify()?; // sanity check
        self.new_transactions.insert(txn.hash(), txn);

        Ok(())
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Option<SignedTransaction> {
        Some(self.transactions.get(&hash)?.clone())
    }

    pub fn get_transaction_receipt(&self, hash: Hash) -> Option<TransactionReceipt> {
        Some(self.transaction_receipts.get(&hash)?.clone())
    }

    fn update_high_qc_and_view(
        &mut self,
        from_agg: bool,
        new_high_qc: QuorumCertificate,
    ) -> Result<()> {
        let Some(new_high_qc_block) = self.block_store.get_block(new_high_qc.block_hash) else {
            // We don't set high_qc to a qc if we don't have its block.
            return Ok(());
        };

        let new_high_qc_block_view = new_high_qc_block.view();

        if self.high_qc.block_hash == Hash::ZERO {
            self.high_qc = new_high_qc;
        } else {
            let current_high_qc_view = self.get_block(&self.high_qc.block_hash)?.view();
            // If `from_agg` then we always release the lock because the supermajority has a different high_qc.
            if from_agg || new_high_qc_block_view > current_high_qc_view {
                self.high_qc = new_high_qc;
            }
        }

        self.download_blocks_up_to(new_high_qc_block_view);

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
    ) -> QuorumCertificate {
        // we've already verified the signatures upon receipt of the responses so there's no need to do it again
        QuorumCertificate {
            signature: NodeSignature::aggregate(signatures).unwrap(),
            cosigned,
            block_hash,
        }
    }

    fn block_extends_from(&self, block: &Block, ancestor: &Block) -> Result<bool> {
        // todo: the block extends from another block through a chain of parent hashes and not qcs
        let mut current = block;
        while current.view() > ancestor.view() {
            current = self.get_block(&current.parent_hash())?;
        }
        Ok(current.view() == 0 || current.hash() == ancestor.hash())
    }

    fn check_safe_block(&mut self, proposal: &Block) -> bool {
        let Ok(qc_block) = self.get_block(&proposal.qc.block_hash) else { trace!("could not get qc for block: {}", proposal.qc.block_hash); return false; };
        // We don't vote on blocks older than our view
        let not_outdated = proposal.view() >= self.view;
        match proposal.agg {
            // we check elsewhere that qc is the highest among the qcs in the agg
            Some(_) => match self.block_extends_from(proposal, qc_block) {
                Ok(true) => {
                    let block_hash = proposal.hash();
                    self.check_and_commit(block_hash);
                    not_outdated
                }
                Ok(false) => {
                    trace!("block does not extend from parent");
                    false
                }
                Err(e) => {
                    trace!(?e, "error checking block extension");
                    false
                }
            },
            None => {
                if proposal.view() == 0 || proposal.view() == qc_block.view() + 1 {
                    self.check_and_commit(proposal.hash());

                    if !not_outdated {
                        trace!("proposal is outdated: {} < {}", proposal.view(), self.view);
                    }

                    not_outdated
                } else {
                    trace!(
                        "block does not extend from parent, {} != {} + 1",
                        proposal.view(),
                        qc_block.view()
                    );
                    false
                }
            }
        }
    }

    fn check_and_commit(&mut self, proposal_hash: Hash) {
        let Ok(proposal) = self.get_block(&proposal_hash) else { trace!("block not found: {proposal_hash}"); return; };
        let Ok(prev_1) = self.get_block(&proposal.qc.block_hash) else { trace!("parent not found: {}", proposal.qc.block_hash); return; };
        let Ok(prev_2) = self.get_block(&prev_1.qc.block_hash) else { trace!("grandparent not found: {}", prev_1.qc.block_hash); return; };

        if prev_1.view() == 0 || prev_1.view() == prev_2.view() + 1 {
            let committed_block = prev_2;
            let finalized_block = self.get_block_by_view(self.finalized_view).unwrap();
            let mut current = committed_block;
            // commit blocks back to the last finalized block
            while current.view() > self.finalized_view {
                let Ok(new) = self.get_block(&current.parent_hash()) else { return; };
                current = new;
            }
            if current.hash() == finalized_block.hash() {
                self.finalized_view = committed_block.view();
                // discard blocks that can't be committed anymore
            }
        } else {
            trace!(
                "parent does not extend from grandparent {} != {} + 1",
                prev_1.view(),
                prev_2.view()
            );
        }
    }

    /// Check the validity of a block
    fn check_block(&mut self, block: &Block) -> Result<()> {
        block.verify_hash()?;

        if block.view() == 0 {
            return Ok(());
        }

        // TODO: Handle missing block error here - Happens if we join the network late, our finalized_view is still 0. We need to get the genesis block!
        let finalized_block = self.get_block_by_view(self.finalized_view)?;
        if block.view() < finalized_block.view() {
            return Err(anyhow!(
                "block is too old: view is {} but we have finalized {}",
                block.view(),
                finalized_block.view()
            ));
        }

        let parent = self.get_block(&block.parent_hash())?;

        // Derive the proposer from the block's view
        let proposer = parent.committee[parent.view() as usize % parent.committee.len()];
        trace!("I think the block proposer is: {}", proposer.peer_id);
        // Verify the proposer's signature on the block
        proposer
            .public_key
            .verify(block.hash().as_bytes(), block.signature())?;
        // Check if the co-signers of the block's QC represent the supermajority.
        self.check_quorum_in_bits(block.view(), &block.qc.cosigned)?;
        // Verify the block's QC signature
        self.verify_qc_signature(&block.qc)?;
        if let Some(agg) = &block.agg {
            // Check if the signers of the block's aggregate QC represent the supermajority
            self.check_quorum_in_indices(block.view(), &agg.signers)?;
            // Verify the aggregate QC's signature
            self.batch_verify_agg_signature(agg)?;
        }

        // Retrieve the highest among the aggregated QCs and check if it equals the block's QC.
        let block_high_qc = self.get_high_qc_from_block(block)?;
        let block_high_qc_block = self.get_block(&block_high_qc.block_hash)?;
        // Prevent the creation of forks from the already committed chain
        if block_high_qc_block.view() < finalized_block.view() {
            return Err(anyhow!("invalid block"));
        }

        // This block's timestamp must be greater than or equal to the parent block's timestamp.
        if block.timestamp() < parent.timestamp() {
            return Err(anyhow!("timestamp decreased from parent"));
        }

        // This block's timestamp must be at most `self.allowed_timestamp_skew` away from the current time. Note this
        // can be either forwards or backwards in time.
        let difference = block
            .timestamp()
            .elapsed()
            .unwrap_or_else(|err| err.duration());
        if difference > self.config.allowed_timestamp_skew {
            return Err(anyhow!(
                "timestamp difference greater than allowed skew: {difference:?}"
            ));
        }

        if !self.block_extends_from(block, finalized_block)? {
            return Err(anyhow!("invalid block"));
        }

        Ok(())
    }

    // Checks for the validity of a block and adds it to our block store if valid.
    pub fn receive_block(&mut self, block: Block) -> Result<()> {
        if self.block_store.contains_block(block.hash()) {
            return Ok(());
        }

        match self.check_block(&block) {
            Ok(()) => {
                self.update_high_qc_and_view(block.agg.is_some(), block.qc.clone())?;
                self.add_block(block);
            }
            Err(e) => {
                // TODO: Downcasting is a bit ugly here - We should probably have an error enum instead.
                if let Some(e) = e.downcast_ref::<MissingBlockError>() {
                    // We don't call `update_high_qc_and_view` here because the block might be a fork of the finalized chain
                    self.add_block(block);
                    match e.0 {
                        BlockRef::Hash(hash) => self.block_store.request_block(hash),
                        BlockRef::View(view) => self.block_store.request_block_by_view(view),
                    }
                } else {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    fn add_block(&mut self, block: Block) {
        let hash = block.hash();
        debug!(?hash, ?block.header.view, "added block");
        self.block_store.process_block(block);
    }

    fn vote_from_block(&self, block: &Block) -> Vote {
        Vote {
            block_hash: block.hash(),
            signature: self.secret_key.sign(block.hash().as_bytes()),
            public_key: self.secret_key.node_public_key(),
        }
    }

    fn get_high_qc_from_block<'a>(&self, block: &'a Block) -> Result<&'a QuorumCertificate> {
        let Some(agg) = &block.agg else { return Ok(&block.qc); };

        let high_qc = self.get_highest_from_agg(agg)?;

        if &block.qc != high_qc {
            return Err(anyhow!("qc mismatch"));
        }

        Ok(&block.qc)
    }

    pub fn get_block(&self, key: &Hash) -> Result<&Block> {
        Ok(self
            .block_store
            .get_block(*key)
            .ok_or(MissingBlockError(BlockRef::Hash(*key)))?)
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<&Block> {
        //if view == 0 {
        //    return Ok(&EMPTY_GENESIS);
        //}

        Ok(self
            .block_store
            .get_block_by_view(view)
            .ok_or(MissingBlockError(BlockRef::View(view)))?)
    }

    pub fn view(&self) -> u64 {
        self.view
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn state_at(&self, view: u64) -> Option<State> {
        let root_hash = self.get_block_by_view(view).ok()?.state_root_hash();
        Some(self.state.at_root(H256(root_hash.0)))
    }

    pub fn try_get_state_at(&self, view: u64) -> Result<State> {
        self.state_at(view)
            .ok_or_else(|| anyhow!("No block at height {view}"))
    }

    pub fn seen_tx_already(&self, hash: &Hash) -> bool {
        self.new_transactions.contains_key(hash) || self.transactions.contains_key(hash)
    }

    fn get_highest_from_agg<'a>(&self, agg: &'a AggregateQc) -> Result<&'a QuorumCertificate> {
        agg.qcs
            .iter()
            .map(|qc| (qc, self.get_block(&qc.block_hash)))
            .try_fold(None, |acc, (qc, block)| {
                if let Some((_, acc_view)) = acc {
                    let block = block?;
                    if acc_view < block.view() {
                        Ok::<_, anyhow::Error>(Some((qc, block.view())))
                    } else {
                        Ok(acc)
                    }
                } else {
                    Ok(Some((qc, block?.view())))
                }
            })?
            .ok_or_else(|| anyhow!("no qcs in agg"))
            .map(|(qc, _)| qc)
    }

    fn verify_qc_signature(&self, _: &QuorumCertificate) -> Result<()> {
        // TODO: Build aggregate signature from public keys and validate `qc.block_hash` against `qc.signature`.
        Ok(())
    }

    fn batch_verify_agg_signature(&self, agg: &AggregateQc) -> Result<()> {
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
        let messages: Vec<_> = messages.iter().map(|m| m.as_slice()).collect();

        let committee = self.committee()?;
        let public_keys: Vec<_> = agg
            .signers
            .iter()
            .map(|i| committee[*i as usize].public_key)
            .collect();

        verify_messages(agg.signature, &messages, &public_keys)
    }

    fn get_leader(&self, view: u64) -> Result<Validator> {
        // currently it's a simple round robin but later
        // we will select the leader based on the weights
        let block = self.get_block_by_view(view - 1)?;
        Ok(block.committee[view as usize % block.committee.len()])
    }

    fn committee_weight(&self, committee: &[Validator]) -> Result<u128> {
        Ok(committee.iter().map(|v| v.weight).sum())
    }

    fn check_quorum_in_bits(&self, view: u64, cosigned: &BitSlice) -> Result<()> {
        let committee = &self.get_block_by_view(view - 1)?.committee;
        let cosigned_sum: u128 = committee
            .iter()
            .enumerate()
            .map(|(i, v)| if cosigned[i] { v.weight } else { 0 })
            .sum();

        if cosigned_sum * 3 <= self.committee_weight(committee)? * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    fn check_quorum_in_indices(&self, view: u64, signers: &[u16]) -> Result<()> {
        let committee = &self.get_block_by_view(view - 1)?.committee;
        let signed_sum: u128 = signers.iter().map(|i| committee[*i as usize].weight).sum();

        if signed_sum * 3 <= self.committee_weight(committee)? * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }
}
