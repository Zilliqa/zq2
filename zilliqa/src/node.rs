use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use bitvec::bitvec;
use itertools::Itertools;
use libp2p::PeerId;
use tokio::sync::mpsc::UnboundedSender;
use tracing::trace;

use crate::{
    crypto::{verify_messages, Hash, PublicKey, SecretKey, Signature},
    message::{
        AggregateQc, BitSlice, BitVec, Block, BlockRequest, BlockResponse, Message, NewView,
        Proposal, QuorumCertificate, Vote,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct Validator {
    pub public_key: PublicKey,
    pub peer_id: PeerId,
    pub weight: u128,
}

struct NewViewVote {
    signatures: Vec<Signature>,
    signers: Vec<u16>,
    cosigned: BitVec,
    cosigned_weight: u128,
    qcs: Vec<QuorumCertificate>,
}

pub struct Node {
    committee: Vec<Validator>,
    blocks: BTreeMap<Hash, Block>,
    votes: BTreeMap<Hash, (Vec<Signature>, BitVec, u128)>,
    new_views: BTreeMap<u64, NewViewVote>,
    high_qc: Option<QuorumCertificate>, // none before we receive the first proposal
    view: u64,
    secret_key: SecretKey,
    /// The latest block in the chain.
    head: Hash,
    /// The latest finalized block.
    finalized: Hash,
    message_sender: UnboundedSender<(PeerId, Message)>,
    reset_timeout: UnboundedSender<()>,
    /// Peers that have appeared between the last view and this one. They will be added to the committee before the next view.
    pending_peers: Vec<(PeerId, PublicKey)>,
}

impl Node {
    pub fn new(
        peer_id: PeerId,
        secret_key: SecretKey,
        message_sender: UnboundedSender<(PeerId, Message)>,
        reset_timeout: UnboundedSender<()>,
    ) -> Result<Node> {
        let validator = Validator {
            public_key: secret_key.public_key(),
            peer_id,
            weight: 100,
        };

        let node = Node {
            committee: vec![validator],
            blocks: BTreeMap::new(),
            votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            high_qc: None,
            view: 0,
            secret_key,
            head: Hash::ZERO,
            finalized: Hash::ZERO,
            message_sender,
            reset_timeout,
            pending_peers: Vec::new(),
        };

        Ok(node)
    }

    // TODO: Multithreading - `&mut self` -> `&self`
    pub fn handle_message(&mut self, source: PeerId, message: Message) -> Result<()> {
        match message {
            Message::Proposal(m) => self.handle_proposal(source, m),
            Message::Vote(m) => self.handle_vote(source, m),
            Message::NewView(m) => self.handle_new_view(source, m),
            Message::BlockRequest(m) => self.handle_block_request(source, m),
            Message::BlockResponse(m) => self.handle_block_response(source, m),
        }
    }

    pub fn handle_timeout(&mut self) -> Result<()> {
        self.update_view(self.view + 1);
        self.reset_timeout.send(())?;

        if let Some(high_qc) = &self.high_qc {
            let new_view = self.new_view_from_qc(high_qc);
            self.send_message(
                self.get_leader(self.view).peer_id,
                Message::NewView(new_view),
            )?;
        }

        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerId, public_key: PublicKey) -> Result<()> {
        if self.pending_peers.contains(&(peer, public_key)) {
            return Ok(());
        }

        self.pending_peers.push((peer, public_key));

        // Before we have at least 3 other nodes (not including ourselves) there is no point trying to propose blocks,
        // because the supermajority condition is impossible to achieve.
        if self.pending_peers.len() >= 3 && self.view == 0 {
            let genesis = Block::genesis(self.committee.len());
            self.high_qc = Some(genesis.qc.clone());
            self.add_block(genesis.clone());
            self.update_view(1);
            let vote = self.vote_from_block(&genesis);
            self.reset_timeout.send(())?;
            let leader = self.get_leader(self.view).peer_id;
            self.send_message(leader, Message::Vote(vote))?;
        }

        Ok(())
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

    fn send_message(&mut self, peer: PeerId, message: Message) -> Result<()> {
        if peer == self.validator().peer_id {
            // We need to 'send' this message to ourselves.
            self.handle_message(peer, message)?;
        } else {
            self.message_sender.send((peer, message))?;
        }
        Ok(())
    }

    fn broadcast_message(&mut self, message: Message) -> Result<()> {
        self.handle_message(self.validator().peer_id, message.clone())?;
        // FIXME: We broadcast everything, so the recipient doesn't matter.
        self.message_sender.send((PeerId::random(), message))?;
        Ok(())
    }

    fn handle_block_request(&mut self, source: PeerId, request: BlockRequest) -> Result<()> {
        let block = self.get_block(&request.hash)?;

        self.send_message(
            source,
            Message::BlockResponse(BlockResponse {
                block: block.clone(),
            }),
        )?;

        Ok(())
    }

    fn handle_block_response(&mut self, _: PeerId, response: BlockResponse) -> Result<()> {
        self.blocks
            .entry(response.block.hash)
            .or_insert(response.block);

        Ok(())
    }

    fn handle_new_view(&mut self, _: PeerId, new_view: NewView) -> Result<()> {
        // if we are not the leader of the round in which the vote counts
        if self.get_leader(new_view.view).public_key != self.secret_key.public_key() {
            trace!(new_view.view, "skipping new view, not the leader");
            return Ok(());
        }
        // if the vote is too old and does not count anymore
        if new_view.view < self.view {
            return Ok(());
        }
        // verify the sender's signature on the block hash
        let mut message = Vec::new();
        message.extend_from_slice(new_view.qc.compute_hash().as_bytes());
        message.extend_from_slice(&new_view.index.to_be_bytes());
        message.extend_from_slice(&new_view.view.to_be_bytes());
        let sender = self.get_member(new_view.index);
        sender.public_key.verify(&message, new_view.signature)?;

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
                let proposal = self.block_from_agg(
                    self.view,
                    high_qc.clone(),
                    agg,
                    self.head,
                    vec![], // replace this with the real commands
                );
                // as a future improvement, process the proposal before broadcasting it
                self.broadcast_message(Message::Proposal(Proposal { block: proposal }))?;
                // we don't want to keep the collected votes if we proposed a new block
                return Ok(());
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

        Ok(())
    }

    fn handle_vote(&mut self, _: PeerId, vote: Vote) -> Result<()> {
        let Ok(block) = self.get_block(&vote.block_hash) else { return Ok(()); }; // TODO: Is this the right response when we recieve a vote for a block we don't know about?
        let block_hash = block.hash;
        let block_view = block.view;
        trace!(block_view, "handling vote");
        // if we are not the leader of the round in which the vote counts
        if self.get_leader(block_view + 1).public_key != self.secret_key.public_key() {
            trace!(vote_view = block_view + 1, "skipping vote, not the leader");
            return Ok(());
        }
        // if the vote is too old and does not count anymore
        if block_view + 1 < self.view {
            return Ok(());
        }
        // verify the sender's signature on block_hash
        let sender = self.get_member(vote.index);
        sender
            .public_key
            .verify(block.hash.as_bytes(), vote.signature)?;

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
                // if the voted block's view is higher than our current head's view then use it as head
                if block_view > self.get_block(&self.head)?.view {
                    self.head = block_hash;
                }
                let qc = self.qc_from_bits(block_hash, &signatures, cosigned.clone());
                let proposal = self.block_from_qc(self.view, qc, self.head, vec![]); // replace this with the real commands
                                                                                     // as a future improvement, process the proposal before broadcasting it
                trace!("vote successful");
                self.broadcast_message(Message::Proposal(Proposal { block: proposal }))?;
                // we don't want to keep the collected votes if we proposed a new block
                return Ok(());
                // we should remove the collected votes if we couldn't reach supermajority within the view
            }
        }
        if !supermajority {
            self.votes
                .insert(block_hash, (signatures, cosigned, cosigned_weight));
        }

        Ok(())
    }

    fn handle_proposal(&mut self, _: PeerId, message: Proposal) -> Result<()> {
        let proposal = message.block;

        // derive the sender from the proposal's view
        let sender = self.get_leader(proposal.view);
        // verify the sender's signature on the proposal
        sender
            .public_key
            .verify(proposal.hash.as_bytes(), proposal.signature)?;
        // in the future check if we already have another block with the same view as proposal, which means that the sender equivocates; also figure out who voted for both of these blocks and thus equivocated
        // check if the co-signers of the proposal's qc represent the supermajority
        self.check_quorum_in_bits(&proposal.qc.cosigned)?;

        // FIXME: Sane validation of genesis blocks
        let proposal_view = proposal.view;
        if proposal_view > 2 {
            // verify the block qc's signature
            self.verify_qc_signature(&proposal.qc)?;
        }

        if let Some(agg) = &proposal.agg {
            // check if the signers of the proposal's agg represent the supermajority
            self.check_quorum_in_indices(&agg.signers)?;

            // verify the block aggregate qc's signature
            self.batch_verify_agg_signature(agg)?;
        }

        // retrieve the highest among the aggregated qcs and check if it equals the block's qc
        let proposal_high_qc = self.get_high_qc_from_block(&proposal)?;

        let mut proposal_high_qc_view = 0;

        match &self.high_qc {
            None => {
                let block_hash = proposal_high_qc.block_hash;
                self.high_qc = Some(proposal_high_qc.clone());
                proposal_high_qc_view = self.get_block(&block_hash)?.view;
            }
            Some(high_qc) => {
                let proposal_high_qc_view = self.get_block(&proposal_high_qc.block_hash)?.view;
                if proposal_high_qc_view > self.get_block(&high_qc.block_hash)?.view {
                    self.high_qc = Some(proposal_high_qc.clone());
                }
            }
        }
        // todo: adjust the node's view if the high_qc's view is higher
        if proposal_high_qc_view > self.view {
            self.update_view(proposal_high_qc_view);
        }
        let vote = self.vote_from_block(&proposal);

        let proposal_view = proposal.view;
        if self.check_safe_block(proposal) {
            // TODO: Download blocks up to `proposal_view - 1`.
            self.update_view(proposal_view + 1);
            self.reset_timeout.send(())?;
            let leader = self.get_leader(self.view).peer_id;
            trace!(proposal_view, "voting for block");
            self.send_message(leader, Message::Vote(vote))?;
        }

        Ok(())
    }

    fn aggregate_qc_from_indexes(
        &self,
        view: u64,
        qcs: Vec<QuorumCertificate>,
        signatures: &[Signature],
        signers: Vec<u16>,
    ) -> Result<AggregateQc> {
        assert_eq!(qcs.len(), signatures.len());
        assert_eq!(signatures.len(), signers.len());
        Ok(AggregateQc {
            signature: Signature::aggregate(signatures)?,
            signers,
            view,
            qcs,
        })
    }

    fn block_from_qc(
        &self,
        view: u64,
        qc: QuorumCertificate,
        parent_hash: Hash,
        commands: Vec<u8>,
    ) -> Block {
        let digest = Hash::compute(&[
            &view.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            // hash of agg missing here intentionally
            parent_hash.as_bytes(),
        ]);
        let signature = self.secret_key.sign(digest.as_bytes());
        Block {
            view,
            qc,
            agg: None,
            hash: digest,
            parent_hash,
            signature,
            commands,
        }
    }

    fn block_from_agg(
        &self,
        view: u64,
        qc: QuorumCertificate,
        agg: AggregateQc,
        parent_hash: Hash,
        commands: Vec<u8>,
    ) -> Block {
        let digest = Hash::compute(&[
            &view.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            agg.compute_hash().as_bytes(),
            parent_hash.as_bytes(),
        ]);
        let signature = self.secret_key.sign(digest.as_bytes());
        Block {
            view,
            qc,
            agg: Some(agg),
            hash: digest,
            parent_hash,
            signature,
            commands,
        }
    }

    fn qc_from_bits(
        &self,
        block_hash: Hash,
        signatures: &[Signature],
        cosigned: BitVec,
    ) -> QuorumCertificate {
        // we've already verified the signatures upon receipt of the responses so there's no need to do it again
        QuorumCertificate {
            signature: Signature::aggregate(signatures).unwrap(),
            cosigned,
            block_hash,
        }
    }

    fn block_extends_from(&self, block: &Block, ancestor: &Block) -> Result<bool> {
        // todo: the block extends from another block through a chain of parent hashes and not qcs
        let mut current = block;
        while current.view > ancestor.view {
            current = self.get_block(&current.parent_hash)?;
        }
        Ok(current.hash == ancestor.hash)
    }

    fn check_safe_block(&mut self, proposal: Block) -> bool {
        let Ok(qc_block) = self.get_block(&proposal.qc.block_hash) else { return false; };
        match proposal.agg {
            // we check elsewhere that qc is the highest among the qcs in the agg
            Some(_) => match self.block_extends_from(&proposal, qc_block) {
                Ok(true) => {
                    let block_hash = proposal.hash;
                    self.add_block(proposal);
                    self.check_and_commit(block_hash);
                    true
                }
                Ok(false) => false,
                Err(_) => {
                    /* todo: we must add the proposed block although a missing block prevented us from checking if it extended from its highest qc's block otherwise we won't have any chance to add it later. if it becomes the head and 2f+1 vote for it, we will use it as parent for proposing a new block in the next round otherwise we won't be able to propose any block unless we receive 2f+1 new view requests. in this case we mustn't use it as parent and hope that 2f+1 have the missing block to conform that our block is safe since if they don't and they add our block just like we added the current one, we end up in an infinite sequence of unsafe blocks noone votes for but everyone uses as parent. therefore we add the proposed block but keep the previous head. if we receive 2f+1 votes for the added block we will store it as head and use it as parent.*/
                    self.blocks.insert(proposal.hash, proposal);
                    false
                }
            },
            None => {
                let not_outdated = proposal.view >= self.view;
                if proposal.view == qc_block.view + 1 {
                    // todo: we store 1-direct chain proposals even if they are outdated and we don't vote for them
                    let hash = proposal.hash;
                    self.add_block(proposal);
                    self.check_and_commit(hash);
                    not_outdated
                } else {
                    false
                }
            }
        }
    }

    fn check_and_commit(&mut self, proposal_hash: Hash) {
        let Ok(proposal) = self.get_block(&proposal_hash) else { return; };
        let Ok(prev_1) = self.get_block(&proposal.qc.block_hash) else { return; };
        let Ok(prev_2) = self.get_block(&prev_1.qc.block_hash) else { return; };

        if prev_1.view == prev_2.view + 1 {
            let committed_block = prev_2;
            let Ok(finalized_block) = self.get_block(&self.finalized) else { return; };
            let mut current = committed_block;
            // commit blocks back to the last finalized block
            while current.view > finalized_block.view {
                let Ok(new) = self.get_block(&current.parent_hash) else { return; };
                current = new;
            }
            if current.hash == self.finalized {
                self.finalized = committed_block.hash;
                // discard blocks that can't be committed anymore
            }
        }
    }

    fn add_block(&mut self, block: Block) {
        let is_higher = self
            .blocks
            .get(&self.head)
            .map(|head| block.view > head.view)
            .unwrap_or(true);
        if is_higher {
            self.head = block.hash;
        }
        trace!(?block.hash, "added block");
        self.blocks.insert(block.hash, block);
    }

    fn vote_from_block(&self, block: &Block) -> Vote {
        Vote {
            block_hash: block.hash,
            signature: self.secret_key.sign(block.hash.as_bytes()),
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

    fn get_block(&self, key: &Hash) -> Result<&Block> {
        self.blocks
            .get(key)
            .ok_or_else(|| anyhow!("block not found: {key:?}"))
    }

    fn get_highest_from_agg<'a>(&self, agg: &'a AggregateQc) -> Result<&'a QuorumCertificate> {
        agg.qcs
            .iter()
            .map(|qc| (qc, self.get_block(&qc.block_hash)))
            .try_fold(None, |acc, (qc, block)| {
                if let Some((_, acc_view)) = acc {
                    let block = block?;
                    if acc_view < block.view {
                        Ok::<_, anyhow::Error>(Some((qc, block.view)))
                    } else {
                        Ok(acc)
                    }
                } else {
                    Ok(Some((qc, block?.view)))
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

    fn new_view_from_qc(&self, qc: &QuorumCertificate) -> NewView {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(qc.compute_hash().as_bytes());
        bytes.extend_from_slice(&self.index().to_be_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());

        NewView {
            signature: self.secret_key.sign(&bytes),
            qc: qc.clone(),
            view: self.view,
            index: self.index(),
        }
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

    fn validator(&self) -> Validator {
        *self
            .committee
            .iter()
            .find(|v| v.public_key == self.secret_key.public_key())
            .expect("node should be in committee")
    }

    /// My own index within the committee.
    fn index(&self) -> u16 {
        self.committee
            .iter()
            .find_position(|v| v.public_key == self.secret_key.public_key())
            .expect("node should be in committee")
            .0 as u16
    }
}
