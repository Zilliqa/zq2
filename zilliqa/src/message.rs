use bitvec::{bitvec, order::Msb0};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{Hash, Signature},
    state::NewTransaction,
};

pub type BitVec = bitvec::vec::BitVec<u8, Msb0>;
pub type BitSlice = bitvec::slice::BitSlice<u8, Msb0>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub block: Block,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// A signature on the block_hash.
    pub signature: Signature,
    pub block_hash: Hash,
    pub index: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewView {
    /// A signature on the view, QC hash and validator index.
    pub signature: Signature,
    pub qc: QuorumCertificate,
    pub view: u64,
    pub index: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub block: Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Proposal(Proposal),
    Vote(Vote),
    NewView(NewView),
    BlockRequest(BlockRequest),
    BlockResponse(BlockResponse),
    NewTransaction(NewTransaction),
}

impl Message {
    pub fn name(&self) -> &'static str {
        match self {
            Message::Proposal(_) => "Proposal",
            Message::Vote(_) => "Vote",
            Message::NewView(_) => "NewView",
            Message::BlockRequest(_) => "BlockRequest",
            Message::BlockResponse(_) => "BlockResponse",
            Message::NewTransaction(_) => "NewTransaction",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub signature: Signature,
    pub cosigned: BitVec,
    pub block_hash: Hash,
}

impl QuorumCertificate {
    pub fn compute_hash(&self) -> Hash {
        Hash::compute(&[
            &self.signature.to_bytes(),
            &self.cosigned.clone().into_vec(), // FIXME: What does this do when `self.cosigned.len() % 8 != 0`?
            self.block_hash.as_bytes(),
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateQc {
    pub signature: Signature,
    pub signers: Vec<u16>,
    pub view: u64,
    pub qcs: Vec<QuorumCertificate>,
}

impl AggregateQc {
    pub fn compute_hash(&self) -> Hash {
        let hashes: Vec<_> = self.qcs.iter().map(|qc| qc.compute_hash()).collect();
        Hash::compute(&[
            &self.signature.to_bytes(),
            &self
                .signers
                .iter()
                .flat_map(|signer| signer.to_be_bytes())
                .collect::<Vec<_>>(),
            Hash::compute(
                &hashes
                    .iter()
                    .map(|hash| hash.as_bytes())
                    .collect::<Vec<_>>(),
            )
            .as_bytes(),
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub view: u64, // the proposer's index can be derived from the block's view
    pub qc: QuorumCertificate,
    pub agg: Option<AggregateQc>,
    pub hash: Hash,
    pub parent_hash: Hash,
    pub signature: Signature,
    pub state_root_hash: u64,
    pub transactions: Vec<Hash>,
}

impl Block {
    pub fn genesis(committee_size: usize) -> Block {
        Block {
            view: 0,
            qc: QuorumCertificate {
                signature: Signature::identity(),
                cosigned: bitvec![u8, bitvec::order::Msb0; 1; committee_size],
                block_hash: Hash::ZERO,
            },
            agg: None,
            hash: Hash::ZERO,
            parent_hash: Hash::ZERO,
            signature: Signature::identity(),
            state_root_hash: 0,
            transactions: vec![],
        }
    }
}
