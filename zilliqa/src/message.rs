use serde::Deserializer;
use std::{fmt::Display, str::FromStr, time::SystemTime};

use anyhow::anyhow;
use anyhow::Result;
use bitvec::{bitvec, order::Msb0};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{
    crypto::{Hash, NodePublicKey, NodeSignature, SecretKey},
    state::SignedTransaction,
};

pub type BitVec = bitvec::vec::BitVec<u8, Msb0>;
pub type BitSlice = bitvec::slice::BitSlice<u8, Msb0>;

/// A block proposal. The only difference between this and [Block] is that `transactions` contains the full transaction
/// bodies, rather than just hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub header: BlockHeader,
    pub qc: QuorumCertificate,
    pub agg: Option<AggregateQc>,
    pub transactions: Vec<SignedTransaction>,
}

impl Proposal {
    pub fn into_parts(self) -> (Block, Vec<SignedTransaction>) {
        (
            Block {
                header: self.header,
                qc: self.qc,
                agg: self.agg,
                transactions: self.transactions.iter().map(|txn| txn.hash()).collect(),
            },
            self.transactions,
        )
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// A signature on the block_hash.
    pub signature: NodeSignature,
    pub block_hash: Hash,
    pub index: u16,
}

impl Vote {
    pub fn new(secret_key: SecretKey, block_hash: Hash, index: u16) -> Self {
        Vote {
            signature: secret_key.sign(block_hash.as_bytes()),
            block_hash,
            index,
        }
    }

    pub fn verify(&self, public_key: NodePublicKey) -> Result<()> {
        public_key.verify(self.block_hash.as_bytes(), self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewView {
    /// A signature on the view, QC hash and validator index.
    pub signature: NodeSignature,
    pub qc: QuorumCertificate,
    pub view: u64,
    pub index: u16,
}

impl NewView {
    pub fn new(secret_key: SecretKey, qc: QuorumCertificate, view: u64, index: u16) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(qc.compute_hash().as_bytes());
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&view.to_be_bytes());

        NewView {
            signature: secret_key.sign(&bytes),
            qc,
            view,
            index,
        }
    }

    pub fn verify(&self, public_key: NodePublicKey) -> Result<()> {
        let mut message = Vec::new();
        message.extend_from_slice(self.qc.compute_hash().as_bytes());
        message.extend_from_slice(&self.index.to_be_bytes());
        message.extend_from_slice(&self.view.to_be_bytes());

        public_key.verify(&message, self.signature)
    }
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
    NewTransaction(SignedTransaction),
    RequestResponse,
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
            Message::RequestResponse => "RequestResponse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// An aggregated signature from `n - f` distinct replicas, built by signing a block hash in a specific view.
    pub signature: NodeSignature,
    pub cosigned: BitVec,
    pub block_hash: Hash,
}

impl QuorumCertificate {
    pub fn genesis(committee_size: usize) -> Self {
        Self {
            signature: NodeSignature::identity(),
            cosigned: bitvec![u8, bitvec::order::Msb0; 1; committee_size],
            block_hash: BlockHeader::genesis_hash(),
        }
    }

    pub fn new(signatures: &[NodeSignature], cosigned: BitVec, block_hash: Hash) -> Self {
        QuorumCertificate {
            signature: NodeSignature::aggregate(signatures).unwrap(),
            cosigned,
            block_hash,
        }
    }

    pub fn compute_hash(&self) -> Hash {
        Hash::compute(&[
            &self.signature.to_bytes(),
            &self.cosigned.clone().into_vec(), // FIXME: What does this do when `self.cosigned.len() % 8 != 0`?
            self.block_hash.as_bytes(),
        ])
    }
}

/// A collection of `n - f` [QuorumCertificate]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateQc {
    pub signature: NodeSignature,
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

/// The [Copy]-able subset of a block.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlockHeader {
    pub view: u64, // the proposer's index can be derived from the block's view
    pub hash: Hash,
    pub parent_hash: Hash,
    pub signature: NodeSignature,
    pub state_root_hash: Hash,
    /// The time this block was mined at.
    pub timestamp: SystemTime,
}

impl BlockHeader {
    pub fn genesis_hash() -> Hash {
        Hash::compute(&[&0_u64.to_be_bytes(), Hash::ZERO.as_bytes()])
    }

    pub fn genesis(state_root_hash: Hash) -> Self {
        Self {
            view: 0,
            hash: BlockHeader::genesis_hash(),
            parent_hash: Hash::ZERO,
            signature: NodeSignature::identity(),
            state_root_hash,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }
}

impl Default for BlockHeader {
    /// Not suitable for use as a real block header.
    fn default() -> Self {
        Self {
            view: 0,
            hash: Hash::ZERO,
            parent_hash: Hash::ZERO,
            signature: NodeSignature::identity(),
            state_root_hash: Hash(Keccak256::digest(rlp::NULL_RLP).into()),
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum BlockNumber {
    Number(u64),
    Earliest,
    Latest,
    Safe,
    Finalized,
    Pending,
}

impl Display for BlockNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Number(num) => num.to_string(),
                Self::Earliest => "earliest".to_string(),
                Self::Latest => "latest".to_string(),
                Self::Safe => "safe".to_string(),
                Self::Finalized => "finalized".to_string(),
                Self::Pending => "pending".to_string(),
            }
        )
    }
}

impl<'de> Deserialize<'de> for BlockNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for BlockNumber {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "earliest" => Ok(BlockNumber::Earliest),
            "latest" => Ok(BlockNumber::Latest),
            "safe" => Ok(BlockNumber::Safe),
            "finalized" => Ok(BlockNumber::Finalized),
            "pending" => Ok(BlockNumber::Pending),
            number => {
                if let Some(number) = number.strip_prefix("0x") {
                    let number = u64::from_str_radix(number, 16)?;
                    Ok(BlockNumber::Number(number))
                } else {
                    Err(anyhow!("invalid block number: {s}"))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    /// A block's quorum certificate (QC) is proof that more than `2n/3` nodes (out of `n`) have voted for this block.
    /// It also includes a pointer to the parent block.
    pub qc: QuorumCertificate,
    /// The block will include an [AggregateQc] if the previous leader failed, meaning we couldn't construct a QC. When
    /// this is not `None`, `qc` will contain a clone of the highest QC within this [AggregateQc];
    pub agg: Option<AggregateQc>,
    pub transactions: Vec<Hash>,
}

impl Block {
    pub fn genesis(committee_size: usize, state_root_hash: Hash) -> Block {
        let qc = QuorumCertificate::genesis(committee_size);
        Block {
            header: BlockHeader::genesis(state_root_hash),
            qc,
            agg: None,
            transactions: vec![],
        }
    }

    pub fn from_qc(
        secret_key: SecretKey,
        view: u64,
        qc: QuorumCertificate,
        parent_hash: Hash,
        state_root_hash: Hash,
        transactions: Vec<Hash>,
        timestamp: SystemTime,
    ) -> Block {
        let digest = Hash::compute(&[
            &view.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            // hash of agg missing here intentionally
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
        ]);
        let signature = secret_key.sign(digest.as_bytes());
        Block {
            header: BlockHeader {
                view,
                hash: digest,
                parent_hash,
                signature,
                state_root_hash,
                timestamp,
            },
            qc,
            agg: None,
            transactions,
        }
    }

    pub fn from_agg(
        secret_key: SecretKey,
        view: u64,
        qc: QuorumCertificate,
        agg: AggregateQc,
        parent_hash: Hash,
        state_root_hash: Hash,
        timestamp: SystemTime,
    ) -> Block {
        let digest = Hash::compute(&[
            &view.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            agg.compute_hash().as_bytes(),
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
        ]);
        let signature = secret_key.sign(digest.as_bytes());
        Block {
            header: BlockHeader {
                view,
                hash: digest,
                parent_hash,
                signature,
                state_root_hash,
                timestamp,
            },
            qc,
            agg: Some(agg),
            transactions: vec![],
        }
    }

    pub fn verify(&self, public_key: NodePublicKey) -> Result<()> {
        public_key.verify(self.header.hash.as_bytes(), self.header.signature)
    }

    pub fn view(&self) -> u64 {
        self.header.view
    }

    pub fn hash(&self) -> Hash {
        self.header.hash
    }

    pub fn parent_hash(&self) -> Hash {
        self.header.parent_hash
    }

    pub fn signature(&self) -> NodeSignature {
        self.header.signature
    }

    pub fn state_root_hash(&self) -> Hash {
        self.header.state_root_hash
    }

    pub fn timestamp(&self) -> SystemTime {
        self.header.timestamp
    }
}
