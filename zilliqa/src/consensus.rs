use primitive_types::H256;
use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use bitvec::bitvec;
use itertools::Itertools;
use libp2p::PeerId;
use sled::{Db, Tree};
use tracing::{debug, trace};

use crate::{
    cfg::Config,
    crypto::{verify_messages, Hash, NodePublicKey, NodeSignature, SecretKey},
    exec::TouchedAddressEventListener,
    exec::TransactionApplyResult,
    message::{
        AggregateQc, BitSlice, BitVec, Block, BlockHeader, NewView, Proposal, QuorumCertificate,
        Vote,
    },
    state::{Address, SignedTransaction, State, TransactionReceipt},
    time::SystemTime,
};

// database tree names
/// Key: trie hash; value: trie node
const STATE_TRIE_TREE: &[u8] = b"state_trie";
/// Key: block hash; value: block header
const BLOCK_HEADERS_TREE: &[u8] = b"block_headers_tree";
/// Key: block number (on the finalized branch); value: block hash
const CANONICAL_BLOCK_NUMBERS_TREE: &[u8] = b"canonical_block_numbers_tree";
/// Key: block hash; value: entire block (with hashes for transactions)
const BLOCKS_TREE: &[u8] = b"blocks_tree";
/// Key: transaction hash; value: transaction data
const TXS_TREE: &[u8] = b"txs_tree";
/// Key: tx hash; value: receipt for it
const RECEIPTS_TREE: &[u8] = b"receipts_tree";
/// Key: address; value: Vec<tx hash where this address was touched>
const ADDR_TOUCHED_INDEX: &[u8] = b"addresses_touched_index";

// single keys stored in default tree in DB
/// value: block hash
const LATEST_FINALIZED_BLOCK_HASH: &[u8] = b"latest_finalized_block_hash";

#[derive(Debug)]
struct NewViewVote {
    signatures: Vec<NodeSignature>,
    signers: Vec<u16>,
    cosigned: BitVec,
    cosigned_weight: u128,
    qcs: Vec<QuorumCertificate>,
}

#[derive(Debug, Clone, Copy)]
pub struct Validator {
    pub public_key: NodePublicKey,
    pub peer_id: PeerId,
    pub weight: u128,
}

#[derive(Debug)]
pub struct Consensus {
    secret_key: SecretKey,
    config: Config,
    committee: Vec<Validator>,
    block_headers: Tree,
    canonical_block_numbers: Tree,
    blocks: Tree,
    votes: BTreeMap<Hash, (Vec<NodeSignature>, BitVec, u128)>,
    new_views: BTreeMap<u64, NewViewVote>,
    high_qc: Option<QuorumCertificate>, // none before we receive the first proposal
    view: u64,
    /// The latest finalized block.
    finalized: Hash,
    /// Peers that have appeared between the last view and this one. They will be added to the committee before the next view.
    pending_peers: Vec<(PeerId, NodePublicKey)>,
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
    pub fn new(secret_key: SecretKey, config: Config) -> Result<Self> {
        let validator = Validator {
            public_key: secret_key.node_public_key(),
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            weight: 100,
        };

        trace!("Opening database at path {:?}", config.data_dir);

        let db = match &config.data_dir {
            Some(path) => sled::open(path)?,
            None => sled::Config::new().temporary(true).open()?,
        };

        let block_headers = db.open_tree(BLOCK_HEADERS_TREE)?;
        let state_trie = db.open_tree(STATE_TRIE_TREE)?;

        let latest_block_header = if let Some(ivec) = db.get(LATEST_FINALIZED_BLOCK_HASH)? {
            let latest_block_hash = bincode::deserialize::<Hash>(&ivec)?;
            let latest_block_header = block_headers
                .get(latest_block_hash.as_bytes())?
                .ok_or(anyhow!("No header found for latest recorded block hash"))?;
            Some(bincode::deserialize::<BlockHeader>(&latest_block_header)?)
        } else {
            None
        };

        let mut state = if let Some(header) = latest_block_header {
            State::new_from_root(state_trie, H256(header.state_root_hash.0))
        } else {
            State::new_genesis(state_trie)?
        };

        let latest_block_header =
            latest_block_header.unwrap_or(BlockHeader::genesis(state.root_hash()?));
        trace!("Loading state at height {}", latest_block_header.view);

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

        Ok(Consensus {
            secret_key,
            config,
            committee: vec![validator],
            block_headers,
            canonical_block_numbers: db.open_tree(CANONICAL_BLOCK_NUMBERS_TREE)?,
            blocks: db.open_tree(BLOCKS_TREE)?,
            votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            high_qc: None,
            view: latest_block_header.view,
            finalized: latest_block_header.hash,
            pending_peers: Vec::new(),
            new_transactions: BTreeMap::new(),
            transactions: db.open_tree(TXS_TREE)?,
            transaction_receipts: db.open_tree(RECEIPTS_TREE)?,
            state,
            db,
            touched_address_index,
        })
    }

    fn update_view(&mut self, view: u64) {
        self.view = view;
        let pending_peers = self.pending_peers.drain(..);

        for (peer_id, public_key) in pending_peers {
            if self
                .committee
                .iter()
                .filter(|v| v.peer_id == peer_id)
                .count()
                > 0
            {
                continue;
            }

            let validator = Validator {
                peer_id,
                public_key,
                weight: 100, // Arbitrary weight
            };
            self.committee.push(validator);
        }
        // We always keep the committee sorted by the peer ID to give a stable ordering across the network.
        self.committee.sort_unstable_by_key(|v| v.peer_id);
    }

    pub fn add_peer(
        &mut self,
        peer: PeerId,
        public_key: NodePublicKey,
    ) -> Result<Option<(PeerId, Vote)>> {
        if self.pending_peers.contains(&(peer, public_key)) {
            return Ok(None);
        }

        debug!(%peer, "added pending peer");

        self.pending_peers.push((peer, public_key));

        // Before we have at least 3 other nodes (not including ourselves) there is no point trying to propose blocks,
        // because the supermajority condition is impossible to achieve.
        if self.pending_peers.len() >= 3 && self.view == 0 {
            let genesis = Block::genesis(self.committee.len(), self.state.root_hash()?);
            self.high_qc = Some(genesis.qc.clone());
            self.add_block(genesis.clone())?;
            self.save_highest_view(genesis.hash(), genesis.view())?;
            // treat genesis as finalized
            self.db
                .insert(LATEST_FINALIZED_BLOCK_HASH, &genesis.hash().0)?;
            self.finalized = genesis.hash();
            self.update_view(1);
            let vote = self.vote_from_block(&genesis);
            let leader = self.get_leader(self.view).peer_id;
            return Ok(Some((leader, vote)));
        }

        Ok(None)
    }

    pub fn timeout(&mut self) -> Result<Option<(PeerId, NewView)>> {
        if self.view == 0 {
            return Ok(None);
        }

        self.update_view(self.view + 1);

        if let Some(high_qc) = &self.high_qc {
            let new_view = NewView::new(self.secret_key, high_qc.clone(), self.view, self.index());
            return Ok(Some((self.get_leader(self.view).peer_id, new_view)));
        }

        Ok(None)
    }

    pub fn proposal(&mut self, proposal: Proposal) -> Result<Option<(PeerId, Vote)>> {
        let (block, transactions) = proposal.into_parts();

        // derive the sender from the proposal's view
        let sender = self.get_leader(block.view());
        // verify the sender's signature on the proposal
        block.verify(sender.public_key)?;
        // in the future check if we already have another block with the same view as proposal, which means that the sender equivocates; also figure out who voted for both of these blocks and thus equivocated
        // check if the co-signers of the proposal's qc represent the supermajority
        self.check_quorum_in_bits(&block.qc.cosigned)?;

        // FIXME: Sane validation of genesis blocks
        let proposal_view = block.view();
        if proposal_view > 2 {
            // verify the block qc's signature
            self.verify_qc_signature(&block.qc)?;
        }

        if let Some(agg) = &block.agg {
            // check if the signers of the proposal's agg represent the supermajority
            self.check_quorum_in_indices(&agg.signers)?;

            // verify the block aggregate qc's signature
            self.batch_verify_agg_signature(agg)?;
        }

        let parent = self.get_block(&block.parent_hash())?;
        let parent_header = parent.header;

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

        // retrieve the highest among the aggregated qcs and check if it equals the block's qc
        let proposal_high_qc = self.get_high_qc_from_block(&block)?;

        self.add_block(block.clone())?;
        self.update_high_qc_and_view(block.agg.is_some(), proposal_high_qc.clone())?;

        let block_state_root = block.state_root_hash();
        if self.check_safe_block(block.clone())? {
            for txn in &transactions {
                if let Some(result) = self.apply_transaction(txn.clone(), parent_header)? {
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
            // TODO: Download blocks up to `proposal_view - 1`.
            self.update_view(proposal_view + 1);
            self.save_highest_view(block.hash(), proposal_view)?;
            let leader = self.get_leader(self.view).peer_id;
            trace!(proposal_view, "voting for block");
            let vote = self.vote_from_block(&block);

            Ok(Some((leader, vote)))
        } else {
            Ok(None)
        }
    }

    pub fn apply_transaction(
        &mut self,
        txn: SignedTransaction,
        current_block: BlockHeader,
    ) -> Result<Option<TransactionApplyResult>> {
        let hash = txn.hash();

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

    pub fn vote(
        &mut self,
        _: PeerId,
        vote: Vote,
    ) -> Result<Option<(Block, Vec<SignedTransaction>)>> {
        let Ok(block) = self.get_block(&vote.block_hash) else { return Ok(None); }; // TODO: Is this the right response when we recieve a vote for a block we don't know about?
        let block_hash = block.hash();
        let block_view = block.view();
        trace!(block_view, self.view, "handling vote");
        // if we are not the leader of the round in which the vote counts
        if self.get_leader(block_view + 1).public_key != self.secret_key.node_public_key() {
            trace!(vote_view = block_view + 1, "skipping vote, not the leader");
            return Ok(None);
        }
        // if the vote is too old and does not count anymore
        if block_view + 1 < self.view {
            return Ok(None);
        }
        // verify the sender's signature on block_hash
        let sender = self.get_member(vote.index);
        vote.verify(sender.public_key)?;

        let (mut signatures, mut cosigned, mut cosigned_weight) =
            self.votes.remove(&block_hash).unwrap_or_else(|| {
                (
                    Vec::new(),
                    bitvec![u8, bitvec::order::Msb0; 0; self.committee.len()],
                    0,
                )
            });

        let mut supermajority = false;
        // if the vote is new, store it
        if !cosigned[vote.index as usize] {
            signatures.push(vote.signature);
            cosigned.set(vote.index as usize, true);
            cosigned_weight += sender.weight;

            supermajority = cosigned_weight * 3 > self.committee_weight() * 2;
            trace!(
                cosigned_weight,
                supermajority,
                self.view,
                vote_view = block_view + 1,
                "storing vote"
            );
            // if we are already in the round in which the vote counts and have reached supermajority
            if block_view + 1 == self.view && supermajority {
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
                        result
                            .transpose()
                            .map(|r| r.map(|r| (tx.clone(), r.success, r.contract_address, r.logs)))
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

                // as a future improvement, process the proposal before broadcasting it
                trace!("vote successful");
                return Ok(Some((proposal, applied_transactions)));
                // we don't want to keep the collected votes if we proposed a new block
                // we should remove the collected votes if we couldn't reach supermajority within the view
            }
        }
        if !supermajority {
            self.votes
                .insert(block_hash, (signatures, cosigned, cosigned_weight));
        }

        Ok(None)
    }

    pub fn new_view(&mut self, _: PeerId, new_view: NewView) -> Result<Option<Block>> {
        // if we are not the leader of the round in which the vote counts
        if self.get_leader(new_view.view).public_key != self.secret_key.node_public_key() {
            trace!(new_view.view, "skipping new view, not the leader");
            return Ok(None);
        }
        // if the vote is too old and does not count anymore
        if new_view.view < self.view {
            return Ok(None);
        }
        // verify the sender's signature on the block hash
        let sender = self.get_member(new_view.index);
        new_view.verify(sender.public_key)?;

        // check if the sender's qc is higher than our high_qc or even higher than our view
        self.update_high_qc_and_view(false, new_view.qc.clone())?;

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
                cosigned: bitvec![u8, bitvec::order::Msb0; 0; self.committee.len()],
                cosigned_weight: 0,
                qcs: Vec::new(),
            });

        let mut supermajority = false;
        // if the vote is new, stores it
        if !cosigned[new_view.index as usize] {
            signatures.push(new_view.signature);
            signers.push(new_view.index);
            cosigned.set(new_view.index as usize, true);
            cosigned_weight += sender.weight;
            qcs.push(new_view.qc);
            supermajority = cosigned_weight * 3 > self.committee_weight() * 2;
            let num_signers = signers.len();
            trace!(
                num_signers,
                cosigned_weight,
                supermajority,
                self.view,
                new_view.view,
                "storing vote for new view"
            );
            // if we are already in the round in which the vote counts and have reached supermajority
            if new_view.view == self.view && supermajority {
                // todo: the aggregate qc is an aggregated signature on the qcs, view and validator index which can be batch verified
                let agg =
                    self.aggregate_qc_from_indexes(new_view.view, qcs, &signatures, signers)?;
                let high_qc = self.get_highest_from_agg(&agg)?;
                let parent_hash = high_qc.block_hash;
                let state_root = self.state.root_hash()?;
                let parent = self.get_block(&parent_hash)?;
                let proposal = Block::from_agg(
                    self.secret_key,
                    self.view,
                    high_qc.clone(),
                    agg,
                    parent_hash,
                    state_root,
                    SystemTime::max(SystemTime::now(), parent.timestamp()),
                );
                // as a future improvement, process the proposal before broadcasting it
                return Ok(Some(proposal));
                // we don't want to keep the collected votes if we proposed a new block
                // we should remove the collected votes if we couldn't reach supermajority within the view
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

    fn save_highest_view(&self, block_hash: Hash, view: u64) -> Result<()> {
        self.canonical_block_numbers
            .insert(view.to_be_bytes(), &block_hash.0)?;
        Ok(())
    }

    fn update_high_qc_and_view(
        &mut self,
        from_agg: bool,
        new_high_qc: QuorumCertificate,
    ) -> Result<()> {
        let new_high_qc_block_hash = new_high_qc.block_hash;
        let Some(new_high_qc_block) = self.blocks.get(new_high_qc_block_hash.0)?
            else {
            // We don't set high_qc to a qc if we don't have its block.
            return Ok(());
        };
        let new_high_qc_block = bincode::deserialize::<Block>(&new_high_qc_block)?;
        match &self.high_qc {
            None => {
                self.high_qc = Some(new_high_qc);
            }
            Some(high_qc) => {
                let current_high_qc_view = self.get_block(&high_qc.block_hash)?.view();
                // If `from_agg` then we always release the lock because the supermajority has a different high_qc.
                if from_agg || new_high_qc_block.view() > current_high_qc_view {
                    self.high_qc = Some(new_high_qc);
                }
            }
        }

        let newview = new_high_qc_block.view();
        // TODO: Download the missing blocks
        self.update_view(newview);
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

    fn block_extends_from(&self, block: Block, ancestor: &Block) -> Result<bool> {
        // todo: the block extends from another block through a chain of parent hashes and not qcs
        let mut current = block;
        while current.view() > ancestor.view() {
            current = self.get_block(&current.parent_hash())?;
        }
        Ok(current.hash() == ancestor.hash())
    }

    fn check_safe_block(&mut self, proposal: Block) -> Result<bool> {
        let Ok(qc_block) = self.get_block(&proposal.qc.block_hash) else { return Ok(false); };
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
                Ok(false) | Err(_) => Ok(false),
            },
            None => {
                if proposal.view() == qc_block.view() + 1 {
                    self.check_and_commit(proposal.hash())?;
                    Ok(not_outdated)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn check_and_commit(&mut self, proposal_hash: Hash) -> Result<()> {
        let Ok(proposal) = self.get_block(&proposal_hash) else { return Ok(()); };
        let Ok(prev_1) = self.get_block(&proposal.qc.block_hash) else { return Ok(()); };
        let Ok(prev_2) = self.get_block(&prev_1.qc.block_hash) else { return Ok(()); };

        if prev_1.view() == prev_2.view() + 1 {
            let committed_block = prev_2;
            let Ok(finalized_block) = self.get_block(&self.finalized) else { return Ok(()); };
            let committed_hash = committed_block.hash();
            let mut current = committed_block;
            // commit blocks back to the last finalized block
            while current.view() > finalized_block.view() {
                let Ok(new) = self.get_block(&current.parent_hash()) else { return Ok(()); };
                current = new;
            }
            if current.hash() == self.finalized {
                self.finalized = committed_hash;
                self.db
                    .insert(LATEST_FINALIZED_BLOCK_HASH, &committed_hash.0)?;
                // discard blocks that can't be committed anymore
            }
        };
        Ok(())
    }

    pub fn add_block(&mut self, block: Block) -> Result<()> {
        let hash = block.hash();
        debug!(?hash, ?block.header.view, "added block");
        self.block_headers
            .insert(hash.as_bytes(), bincode::serialize(&block.header)?)?;
        self.blocks.insert(hash.0, bincode::serialize(&block)?)?;
        Ok(())
    }

    fn vote_from_block(&self, block: &Block) -> Vote {
        Vote {
            block_hash: block.hash(),
            signature: self.secret_key.sign(block.hash().as_bytes()),
            index: self.index(),
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

    pub fn get_block(&self, key: &Hash) -> Result<Block> {
        self.maybe_get_block(key)?
            .ok_or(anyhow!("Block {key} not found"))
    }

    pub fn maybe_get_block(&self, key: &Hash) -> Result<Option<Block>> {
        self.blocks
            .get(key.0)?
            .map(|encoded| Ok(bincode::deserialize::<Block>(&encoded)?))
            .transpose()
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        let block_hash = self.canonical_block_numbers.get(view.to_be_bytes())?;
        if let Some(ivec) = block_hash {
            let block_hash = bincode::deserialize::<Hash>(&ivec)?;
            let block = self
                .blocks
                .get(block_hash.0)?
                .ok_or(anyhow!("Block not found for hash {}", block_hash))?;
            Ok(Some(bincode::deserialize::<Block>(&block)?))
        } else {
            Ok(None)
        }
    }

    pub fn view(&self) -> u64 {
        self.view
    }

    pub fn finalized_view(&self) -> Result<u64> {
        Ok(bincode::deserialize::<BlockHeader>(
            &self
                .block_headers
                .get(self.finalized.as_bytes())?
                .unwrap_or_else(|| {
                    panic!(
                        "No block found for header {}, this should not be possible. Database state is not correct.",
                        self.finalized,
                    )
                }),
        )?
        .view)
    }

    pub fn finalized(&self) -> Hash {
        self.finalized
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

        let public_keys: Vec<_> = agg
            .signers
            .iter()
            .map(|i| self.committee[*i as usize].public_key)
            .collect();

        verify_messages(agg.signature, &messages, &public_keys)
    }

    fn get_leader(&self, view: u64) -> Validator {
        // currently it's a simple round robin but later
        // we will select the leader based on the weights
        self.committee[(view % (self.committee.len() as u64)) as usize]
    }

    fn get_member(&self, index: u16) -> Validator {
        self.committee[index as usize]
    }

    fn committee_weight(&self) -> u128 {
        self.committee.iter().map(|v| v.weight).sum()
    }

    fn check_quorum_in_bits(&self, cosigned: &BitSlice) -> Result<()> {
        let cosigned_sum: u128 = self
            .committee
            .iter()
            .enumerate()
            .map(|(i, v)| if cosigned[i] { v.weight } else { 0 })
            .sum();

        if cosigned_sum * 3 <= self.committee_weight() * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    fn check_quorum_in_indices(&self, signers: &[u16]) -> Result<()> {
        let signed_sum: u128 = signers
            .iter()
            .map(|i| self.committee[*i as usize].weight)
            .sum();

        if signed_sum * 3 <= self.committee_weight() * 2 {
            return Err(anyhow!("no quorum"));
        }

        Ok(())
    }

    /// My own index within the committee.
    fn index(&self) -> u16 {
        self.committee
            .iter()
            .find_position(|v| v.public_key == self.secret_key.node_public_key())
            .expect("node should be in committee")
            .0 as u16
    }
}
