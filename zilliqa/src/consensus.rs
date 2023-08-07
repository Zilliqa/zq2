use anyhow::{anyhow, Result};
use bitvec::bitvec;
use libp2p::PeerId;
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use std::{collections::BTreeMap, error::Error, fmt::Display};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, trace};

use crate::message::{Committee, Message};
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

// database tree names
/// Key: trie hash; value: trie node
const STATE_TRIE_TREE: &[u8] = b"state_trie";
/// Key: transaction hash; value: transaction data
const TXS_TREE: &[u8] = b"txs_tree";
/// Key: tx hash; value: receipt for it
const RECEIPTS_TREE: &[u8] = b"receipts_tree";
/// Key: address; value: Vec<tx hash where this address was touched>
const ADDR_TOUCHED_INDEX: &[u8] = b"addresses_touched_index";

// single keys stored in default tree in DB
/// value: u64
const LATEST_FINALIZED_VIEW: &[u8] = b"latest_finalized_view";

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
    pub weight: u128,
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
    transactions: Tree,
    transaction_receipts: Tree,
    /// The account store.
    state: State,
    /// The persistence database
    db: Db,
    /// An index of address to a list of transaction hashes, for which this address appeared somewhere in the
    /// transaction trace. The list of transations is ordered by execution order.
    touched_address_index: Tree,
}

impl Consensus {
    pub fn new(
        secret_key: SecretKey,
        config: Config,
        message_sender: UnboundedSender<(Option<PeerId>, Message)>,
    ) -> Result<Self> {
        trace!("Opening database at path {:?}", config.data_dir);

        let db = match &config.data_dir {
            Some(path) => sled::open(path)?,
            None => sled::Config::new().temporary(true).open()?,
        };

        let block_store = BlockStore::new(&db, message_sender)?;

        let state_trie = db.open_tree(STATE_TRIE_TREE)?;

        let latest_block = db
            .get(LATEST_FINALIZED_VIEW)?
            .map(|b| Ok::<_, anyhow::Error>(u64::from_be_bytes(b.as_ref().try_into()?)))
            .transpose()?
            .map(|view| {
                block_store
                    .get_block_by_view(view)?
                    .ok_or_else(|| anyhow!("no header found at view {view}"))
            })
            .transpose()?;

        let mut state = if let Some(latest_block) = &latest_block {
            State::new_from_root(state_trie, H256(latest_block.state_root_hash().0))
        } else {
            State::new_genesis(state_trie)?
        };

        let latest_block = match latest_block {
            Some(l) => l,
            None => {
                if config.genesis_committee.len() != 1 {
                    return Err(anyhow!(
                        "genesis committee must have length 1, not {}",
                        config.genesis_committee.len()
                    ));
                }
                let (public_key, peer_id) = config.genesis_committee[0];
                let genesis_validator = Validator {
                    public_key,
                    peer_id,
                    weight: 100,
                };
                Block::genesis(Committee::new(genesis_validator), state.root_hash()?)
            }
        };
        trace!("Loading state at height {}", latest_block.view());

        let touched_address_index = db.open_tree(ADDR_TOUCHED_INDEX)?;
        touched_address_index.set_merge_operator(|_k, old_value, additional_value| {
            // We unwrap all errors as we assume that the serialization should always be correct.
            // TODO: maybe use a smarter packing rather than calling bincode twice every time?
            let mut vec = if let Some(old_value) = old_value {
                bincode::deserialize::<Vec<Hash>>(old_value).unwrap()
            } else {
                vec![]
            };
            vec.push(Hash(additional_value.try_into().unwrap()));
            Some(bincode::serialize(&vec).unwrap())
        });

        let mut consensus = Consensus {
            secret_key,
            config,
            block_store,
            votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            high_qc: QuorumCertificate::genesis(1024), // TODO: Restore `high_qc` from persistence
            view: latest_block.view(),
            finalized_view: latest_block.view(),
            pending_peers: Vec::new(),
            new_transactions: BTreeMap::new(),
            transactions: db.open_tree(TXS_TREE)?,
            transaction_receipts: db.open_tree(RECEIPTS_TREE)?,
            state,
            db,
            touched_address_index,
        };

        // If we're at genesis, add the genesis block.
        if latest_block.view() == 0 {
            consensus.add_block(latest_block.clone())?;
            consensus.save_highest_view(latest_block.hash(), latest_block.view())?;
            // treat genesis as finalized
            consensus
                .db
                .insert(LATEST_FINALIZED_VIEW, &latest_block.view().to_be_bytes())?;
            consensus.finalized_view = latest_block.view();
            consensus.view = 1;
        }

        Ok(consensus)
    }

    pub fn get_chain_tip(&self) -> u64 {
        self.view.saturating_sub(1)
    }

    fn committee(&self) -> Result<Committee> {
        let block = self
            .get_block_by_view(self.get_chain_tip())?
            .ok_or_else(|| anyhow!("missing block"))?;
        Ok(block.committee)
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
            let genesis = self
                .get_block_by_view(0)?
                .ok_or_else(|| anyhow!("missing block"))?;
            // If we're in the genesis committee, vote again.
            if genesis.committee.iter().any(|v| v.peer_id == me) {
                trace!("voting for genesis block");
                let leader = self.get_leader(self.view)?;
                let vote = self.vote_from_block(&genesis);
                return Ok(Some((Some(leader.peer_id), Message::Vote(vote))));
            }
        }

        Ok(None)
    }

    fn download_blocks_up_to(&mut self, to: u64) -> Result<()> {
        for view in (self.view + 1)..to {
            self.view = view;
            self.block_store.request_block_by_view(view)?;
        }
        self.view = to + 1;

        Ok(())
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

        if self.block_store.contains_block(block.hash())? {
            trace!("ignoring block proposal, block store contains this block already");
            return Ok(None);
        }

        match self.check_block(&block) {
            Ok(()) => {}
            Err(e) => {
                if let Some(e) = e.downcast_ref::<MissingBlockError>() {
                    trace!(?e, "missing block");
                    match e.0 {
                        BlockRef::Hash(hash) => self.block_store.request_block(hash)?,
                        BlockRef::View(view) => self.block_store.request_block_by_view(view)?,
                    }

                    self.add_block(block)?;

                    return Ok(None);
                } else {
                    return Err(e);
                }
            }
        }

        self.add_block(block.clone())?;
        self.update_high_qc_and_view(block.agg.is_some(), block.qc.clone())?;

        let proposal_view = block.view();
        let parent = self
            .get_block(&block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block"))?;
        let next_leader = block.committee.leader(proposal_view).peer_id;
        let block_state_root = block.state_root_hash();

        // If the proposed block is safe, vote for it and advance to the next round.
        trace!("checking whether block is safe");
        if self.check_safe_block(&block)? {
            trace!("block is safe");

            for txn in &transactions {
                if let Some(result) = self.apply_transaction(txn.clone(), parent.header)? {
                    let receipt = TransactionReceipt {
                        block_hash: block.hash(),
                        success: result.success,
                        contract_address: result.contract_address,
                        logs: result.logs,
                    };
                    self.transaction_receipts
                        .insert(txn.hash().0, bincode::serialize(&receipt)?)?;
                }
            }
            if self.state.root_hash()? != block_state_root {
                return Err(anyhow!(
                    "state root hash mismatch, expected: {:?}, actual: {:?}",
                    block_state_root,
                    self.state.root_hash()
                ));
            }
            self.download_blocks_up_to(proposal_view.saturating_sub(1))?;
            self.view = proposal_view + 1;
            self.save_highest_view(block.hash(), proposal_view)?;

            let me = self.secret_key.to_libp2p_keypair().public().to_peer_id();
            if !block.committee.iter().any(|v| v.peer_id == me) {
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
        if !self.transactions.contains_key(hash.0)? {
            let mut listener = TouchedAddressEventListener::default();
            let result = evm_ds::evm::tracing::using(&mut listener, || {
                self.state
                    .apply_transaction(txn.clone(), self.config.eth_chain_id, current_block)
            })?;
            self.transactions
                .insert(hash.0, bincode::serialize(&txn)?)?;
            for address in listener.touched {
                self.touched_address_index.merge(address.0, hash.0)?;
            }
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.touched_address_index
            .get(address.0)?
            .map(|encoded| Ok(bincode::deserialize::<Vec<Hash>>(&encoded)?))
            .transpose()
            .map(|opt| opt.unwrap_or_default())
    }

    pub fn vote(&mut self, vote: Vote) -> Result<Option<(Block, Vec<SignedTransaction>)>> {
        let Some(block) = self.get_block(&vote.block_hash)? else { return Ok(None); }; // TODO: Is this the right response when we recieve a vote for a block we don't know about?
        let block_hash = block.hash();
        let block_view = block.view();
        trace!(block_view, self.view, %block_hash, "handling vote");

        // if we are not the leader of the round in which the vote counts
        if block.committee.leader(block_view).public_key != self.secret_key.node_public_key() {
            trace!(vote_view = block_view + 1, "skipping vote, not the leader");
            return Ok(None);
        }
        // if the vote is too old and does not count anymore
        if block_view + 1 < self.view {
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
            trace!("supermajority already reached in this round");
            return Ok(None);
        }

        let mut supermajority = false;
        // if the vote is new, store it
        if !cosigned[index] {
            signatures.push(vote.signature);
            cosigned.set(index, true);
            cosigned_weight += sender.weight;

            supermajority = cosigned_weight * 3 > block.committee.total_weight() * 2;
            trace!(
                cosigned_weight,
                supermajority,
                self.view,
                vote_view = block_view + 1,
                "storing vote"
            );
            if supermajority {
                self.block_store.request_block_by_view(block_view)?;
                self.download_blocks_up_to(block_view)?;

                // if we are already in the round in which the vote counts and have reached supermajority
                if block_view + 1 == self.view {
                    let qc = self.qc_from_bits(block_hash, &signatures, cosigned.clone());
                    let parent_hash = qc.block_hash;
                    let parent = self
                        .get_block(&parent_hash)?
                        .ok_or_else(|| anyhow!("missing block"))?;
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

                    let applied_transactions: Result<Vec<_>> = applied_transactions
                        .into_iter()
                        .map(|(tx, success, contract_address, logs)| {
                            self.transactions
                                .insert(tx.hash().0, bincode::serialize(&tx)?)?;
                            let receipt = TransactionReceipt {
                                block_hash: proposal.hash(),
                                success,
                                contract_address,
                                logs,
                            };
                            self.transaction_receipts
                                .insert(tx.hash().0, bincode::serialize(&receipt)?)?;
                            Ok(tx)
                        })
                        .collect();

                    let applied_transactions = applied_transactions?;

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

    fn get_next_committee(&mut self) -> Result<Committee> {
        let mut committee = self.committee()?.clone();
        committee.add_validators(self.pending_peers.drain(..));
        Ok(committee)
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
        let committee = self.committee()?;
        // verify the sender's signature on the block hash
        let Some((index, sender)) = committee
            .iter()
            .enumerate()
            .find(|(_, v)| v.public_key == new_view.public_key) else {
                debug!("ignoring new view from unknown node (buffer?)");
                return Ok(None);
            };
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
            supermajority = cosigned_weight * 3 > 99999 /* total weight of what committee? */ * 2;
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
                self.download_blocks_up_to(new_view.view - 1)?;

                // if we are already in the round in which the vote counts and have reached supermajority
                if new_view.view == self.view {
                    // todo: the aggregate qc is an aggregated signature on the qcs, view and validator index which can be batch verified
                    let agg =
                        self.aggregate_qc_from_indexes(new_view.view, qcs, &signatures, signers)?;
                    let high_qc = self.get_highest_from_agg(&agg)?;
                    let parent_hash = high_qc.block_hash;
                    let state_root_hash = self.state.root_hash()?;
                    let parent = self
                        .get_block(&parent_hash)?
                        .ok_or_else(|| anyhow!("missing block"))?;
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

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<SignedTransaction>> {
        if let Some(txn) = self.new_transactions.get(&hash) {
            return Ok(Some(txn.clone()));
        }

        self.transactions
            .get(hash.0)?
            .map(|encoded| Ok(bincode::deserialize::<SignedTransaction>(&encoded)?))
            .transpose()
    }

    pub fn get_transaction_receipt(&self, hash: Hash) -> Result<Option<TransactionReceipt>> {
        self.transaction_receipts
            .get(hash.0)?
            .map(|encoded| Ok(bincode::deserialize::<TransactionReceipt>(&encoded)?))
            .transpose()
    }

    fn save_highest_view(&mut self, block_hash: Hash, view: u64) -> Result<()> {
        self.block_store.set_canonical(view, block_hash)?;
        Ok(())
    }

    fn update_high_qc_and_view(
        &mut self,
        from_agg: bool,
        new_high_qc: QuorumCertificate,
    ) -> Result<()> {
        let Some(new_high_qc_block) = self.block_store.get_block(new_high_qc.block_hash)? else {
            // We don't set high_qc to a qc if we don't have its block.
            return Ok(());
        };

        let new_high_qc_block_view = new_high_qc_block.view();

        if self.high_qc.block_hash == Hash::ZERO {
            self.high_qc = new_high_qc;
        } else {
            let current_high_qc_view = self
                .get_block(&self.high_qc.block_hash)?
                .ok_or_else(|| anyhow!("missing block"))?
                .view();
            // If `from_agg` then we always release the lock because the supermajority has a different high_qc.
            if from_agg || new_high_qc_block_view > current_high_qc_view {
                self.high_qc = new_high_qc;
            }
        }

        self.download_blocks_up_to(new_high_qc_block_view)?;

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
        let mut current = block.clone();
        while current.view() > ancestor.view() {
            let Some(next) = self.get_block(&current.parent_hash())? else { return Err(MissingBlockError::from(current.parent_hash()).into()); };
            current = next;
        }
        Ok(current.view() == 0 || current.hash() == ancestor.hash())
    }

    fn check_safe_block(&mut self, proposal: &Block) -> Result<bool> {
        let Some(qc_block) = self.get_block(&proposal.qc.block_hash)? else { trace!("could not get qc for block: {}", proposal.qc.block_hash); return Ok(false); };
        // We don't vote on blocks older than our view
        let not_outdated = proposal.view() >= self.view;
        let proposal_hash = proposal.hash();
        match proposal.agg {
            // we check elsewhere that qc is the highest among the qcs in the agg
            Some(_) => match self.block_extends_from(proposal, &qc_block) {
                Ok(true) => {
                    let block_hash = proposal_hash;
                    self.check_and_commit(block_hash)?;
                    Ok(not_outdated)
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
                    self.check_and_commit(proposal.hash())?;

                    if !not_outdated {
                        trace!("proposal is outdated: {} < {}", proposal.view(), self.view);
                    }

                    Ok(not_outdated)
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

    fn check_and_commit(&mut self, proposal_hash: Hash) -> Result<()> {
        let Some(proposal) = self.get_block(&proposal_hash)? else { trace!("block not found: {proposal_hash}"); return Ok(()); };
        let Some(prev_1) = self.get_block(&proposal.qc.block_hash)? else { trace!("parent not found: {}", proposal.qc.block_hash); return Ok(()); };
        let Some(prev_2) = self.get_block(&prev_1.qc.block_hash)? else { trace!("grandparent not found: {}", prev_1.qc.block_hash); return Ok(()); };

        if prev_1.view() == 0 || prev_1.view() == prev_2.view() + 1 {
            let committed_block = prev_2;
            let committed_block_view = committed_block.view();
            let finalized_block = self
                .get_block_by_view(self.finalized_view)?
                .ok_or_else(|| anyhow!("missing block"))?;
            let mut current = committed_block;
            // commit blocks back to the last finalized block
            while current.view() > self.finalized_view {
                let Some(new) = self.get_block(&current.parent_hash())? else { return Ok(()); };
                current = new;
            }
            if current.hash() == finalized_block.hash() {
                self.finalized_view = committed_block_view;
                self.db
                    .insert(LATEST_FINALIZED_VIEW, &committed_block_view.to_be_bytes())?;
                // discard blocks that can't be committed anymore
            }
        } else {
            trace!(
                "parent does not extend from grandparent {} != {} + 1",
                prev_1.view(),
                prev_2.view(),
            );
        }

        Ok(())
    }

    /// Check the validity of a block
    fn check_block(&mut self, block: &Block) -> Result<()> {
        block.verify_hash()?;

        if block.view() == 0 {
            return Ok(());
        }

        let Some(finalized_block) = self.get_block_by_view(self.finalized_view)? else { return Err(MissingBlockError::from(self.finalized_view).into()); };
        if block.view() < finalized_block.view() {
            return Err(anyhow!(
                "block is too old: view is {} but we have finalized {}",
                block.view(),
                finalized_block.view()
            ));
        }

        let Some(parent) = self.get_block(&block.parent_hash())? else { return Err(MissingBlockError::from(block.parent_hash()).into()); };

        // Derive the proposer from the block's view
        let proposer = parent.committee.leader(parent.view());
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
        let Some(block_high_qc_block) = self.get_block(&block_high_qc.block_hash)? else { return Err(MissingBlockError::from(block_high_qc.block_hash).into()); };
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

        if !self.block_extends_from(block, &finalized_block)? {
            return Err(anyhow!("invalid block"));
        }

        Ok(())
    }

    // Checks for the validity of a block and adds it to our block store if valid.
    pub fn receive_block(&mut self, block: Block) -> Result<()> {
        if self.block_store.contains_block(block.hash())? {
            return Ok(());
        }

        match self.check_block(&block) {
            Ok(()) => {
                self.update_high_qc_and_view(block.agg.is_some(), block.qc.clone())?;
                self.add_block(block)?;
            }
            Err(e) => {
                // TODO: Downcasting is a bit ugly here - We should probably have an error enum instead.
                if let Some(e) = e.downcast_ref::<MissingBlockError>() {
                    // We don't call `update_high_qc_and_view` here because the block might be a fork of the finalized chain
                    self.add_block(block)?;
                    match e.0 {
                        BlockRef::Hash(hash) => self.block_store.request_block(hash),
                        BlockRef::View(view) => self.block_store.request_block_by_view(view),
                    }?
                } else {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    fn add_block(&mut self, block: Block) -> Result<()> {
        let hash = block.hash();
        debug!(?hash, ?block.header.view, "added block");
        self.block_store.process_block(block)?;
        Ok(())
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

    pub fn get_block(&self, key: &Hash) -> Result<Option<Block>> {
        self.block_store.get_block(*key)
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        self.block_store.get_block_by_view(view)
    }

    pub fn view(&self) -> u64 {
        self.view
    }

    pub fn finalized_view(&self) -> u64 {
        self.finalized_view
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn state_at(&self, view: u64) -> Result<Option<State>> {
        Ok(self
            .get_block_by_view(view)?
            .map(|block| self.state.at_root(H256(block.state_root_hash().0))))
    }

    pub fn try_get_state_at(&self, view: u64) -> Result<State> {
        self.state_at(view)?
            .ok_or_else(|| anyhow!("No block at height {view}"))
    }

    pub fn seen_tx_already(&self, hash: &Hash) -> Result<bool> {
        Ok(self.new_transactions.contains_key(hash) || self.transactions.contains_key(hash.0)?)
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
            .map(|i| committee.get_by_index(*i as usize).unwrap().public_key)
            .collect();

        verify_messages(agg.signature, &messages, &public_keys)
    }

    fn get_leader(&self, view: u64) -> Result<Validator> {
        // currently it's a simple round robin but later
        // we will select the leader based on the weights
        // Get the previous block, so we know the committee, then calculate the leader from there.
        let block = self
            .get_block_by_view(view - 1)?
            .ok_or_else(|| anyhow!("missing block"))?;
        Ok(block.committee.leader(view))
    }

    fn check_quorum_in_bits(&self, view: u64, cosigned: &BitSlice) -> Result<()> {
        let committee = &self
            .get_block_by_view(view - 1)?
            .ok_or_else(|| anyhow!("missing block"))?
            .committee;
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

    fn check_quorum_in_indices(&self, view: u64, signers: &[u16]) -> Result<()> {
        let committee = &self
            .get_block_by_view(view - 1)?
            .ok_or_else(|| anyhow!("missing block"))?
            .committee;
        let signed_sum: u128 = signers
            .iter()
            .map(|i| committee.get_by_index(*i as usize).unwrap().weight)
            .sum();

        if signed_sum * 3 <= committee.total_weight() * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }
}
