use std::{
    collections::HashSet,
    fmt,
    fmt::{Display, Formatter},
};

use alloy_primitives::Address;
use anyhow::{anyhow, Result};
use bitvec::{bitvec, order::Msb0};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{
    crypto::{Hash, NodePublicKey, NodeSignature, SecretKey},
    time::SystemTime,
    transaction::{EvmGas, SignedTransaction, VerifiedTransaction},
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
    pub opaque_transactions: Vec<Hash>,
}

impl Proposal {
    /// Constructs a Proposal from a block and a vector of verified transactions.
    /// ```Arguments```
    ///
    /// * `block`: the Block, including the header and the full list of transaction hashes
    /// included in the block (and proposal)
    ///
    /// * `full_transactions`: the transactions whose full `Transaction` bodies will be
    /// included in the proposal. The difference between `block.transactions` and
    /// `full_transactions` make up the `opaque_transactions` (i.e. transactions only known
    /// by their hash).
    pub fn from_parts(block: Block, full_transactions: Vec<VerifiedTransaction>) -> Self {
        Self::from_parts_with_hashes(
            block,
            full_transactions
                .into_iter()
                .map(|tx| (tx.tx, tx.hash))
                .collect(),
        )
    }

    /// Constructs a Proposal from a block and a vector of transactions alongside their hashes.
    /// This is analogous to `Proposal::from_parts()`, except for taking pairs of
    /// `(SignedTransaction, Hash)` instead of `VerifiedTransaction`s, to allow skipping
    /// verification calculations when it isn't relevant.
    pub fn from_parts_with_hashes(
        block: Block,
        full_transactions: Vec<(SignedTransaction, Hash)>,
    ) -> Self {
        let (tx_bodies, tx_hashes): (Vec<SignedTransaction>, HashSet<Hash>) =
            full_transactions.into_iter().unzip();
        Proposal {
            header: block.header,
            qc: block.qc,
            agg: block.agg,
            transactions: tx_bodies,
            opaque_transactions: block
                .transactions
                .into_iter()
                .filter(|hash| !tx_hashes.contains(hash))
                .collect(),
        }
    }

    pub fn into_parts(self) -> (Block, Vec<SignedTransaction>) {
        (
            Block {
                header: self.header,
                qc: self.qc,
                agg: self.agg,
                transactions: self
                    .transactions
                    .iter()
                    .map(|txn| txn.calculate_hash())
                    .chain(self.opaque_transactions)
                    .collect(),
            },
            self.transactions,
        )
    }

    pub fn number(&self) -> u64 {
        self.header.number
    }

    pub fn view(&self) -> u64 {
        self.header.view
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// A signature on the block_hash and view.
    signature: NodeSignature,
    pub block_hash: Hash,
    pub public_key: NodePublicKey,
    pub view: u64,
}

impl Vote {
    pub fn new(
        secret_key: SecretKey,
        block_hash: Hash,
        public_key: NodePublicKey,
        view: u64,
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(block_hash.as_bytes());
        bytes.extend_from_slice(&view.to_be_bytes());

        Vote {
            signature: secret_key.sign(&bytes),
            block_hash,
            public_key,
            view,
        }
    }

    // Make this a getter to force the use of ::new
    pub fn signature(&self) -> NodeSignature {
        self.signature
    }

    pub fn verify(&self) -> Result<()> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());

        self.public_key.verify(&bytes, self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewView {
    /// A signature on the view, QC hash and validator index.
    pub signature: NodeSignature,
    pub qc: QuorumCertificate,
    pub view: u64,
    pub public_key: NodePublicKey,
}

impl NewView {
    pub fn new(
        secret_key: SecretKey,
        qc: QuorumCertificate,
        view: u64,
        public_key: NodePublicKey,
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(qc.compute_hash().as_bytes());
        bytes.extend_from_slice(&public_key.as_bytes());
        bytes.extend_from_slice(&view.to_be_bytes());

        NewView {
            signature: secret_key.sign(&bytes),
            qc,
            view,
            public_key,
        }
    }

    pub fn verify(&self, public_key: NodePublicKey) -> Result<()> {
        let mut message = Vec::new();
        message.extend_from_slice(self.qc.compute_hash().as_bytes());
        message.extend_from_slice(&self.public_key.as_bytes());
        message.extend_from_slice(&self.view.to_be_bytes());

        public_key.verify(&message, self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest(pub BlockRef);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBatchRequest(pub BlockRef);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub proposal: Proposal,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBatchResponse {
    pub proposals: Vec<Proposal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntershardCall {
    pub source_address: Address,
    pub target_address: Option<Address>,
    pub source_chain_id: u64,
    pub bridge_nonce: u64,
    pub calldata: Vec<u8>,
    pub gas_price: u128,
    pub gas_limit: EvmGas,
}

/// A message intended to be sent over the network as part of p2p communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExternalMessage {
    Proposal(Proposal),
    Vote(Box<Vote>),
    NewView(Box<NewView>),
    BlockRequest(BlockRequest),
    BlockResponse(BlockResponse),
    BlockBatchRequest(BlockBatchRequest),
    BlockBatchResponse(BlockBatchResponse),
    NewTransaction(SignedTransaction),
    RequestResponse,
}

impl ExternalMessage {
    pub fn into_proposal(self) -> Option<Proposal> {
        match self {
            ExternalMessage::Proposal(p) => Some(p),
            _ => None,
        }
    }
}

/// A message intended only for local communication between shard nodes and/or the parent p2p node,
/// but not sent over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InternalMessage {
    /// Notifies the coordinator process to spawn a node of the given shard
    LaunchShard(u64),
    /// Notifes the destination shard to start bridging from the given source shard
    LaunchLink(u64),
    /// Routes intershard call information between two locally running, bridged, shard processes
    IntershardCall(IntershardCall),
}

impl ExternalMessage {
    pub fn name(&self) -> &'static str {
        match self {
            ExternalMessage::Proposal(_) => "Proposal",
            ExternalMessage::Vote(_) => "Vote",
            ExternalMessage::NewView(_) => "NewView",
            ExternalMessage::BlockRequest(_) => "BlockRequest",
            ExternalMessage::BlockResponse(_) => "BlockResponse",
            ExternalMessage::BlockBatchRequest(_) => "BlockBatchRequest",
            ExternalMessage::BlockBatchResponse(_) => "BlockBatchResponse",
            ExternalMessage::NewTransaction(_) => "NewTransaction",
            ExternalMessage::RequestResponse => "RequestResponse",
        }
    }
}

impl InternalMessage {
    pub fn name(&self) -> &'static str {
        match self {
            InternalMessage::LaunchShard(_) => "LaunchShard",
            InternalMessage::LaunchLink(_) => "LaunchLink",
            InternalMessage::IntershardCall(_) => "IntershardCall",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// An aggregated signature from `n - f` distinct replicas, built by signing a block hash in a specific view.
    pub signature: NodeSignature,
    pub cosigned: BitVec,
    pub block_hash: Hash,
    pub view: u64,
}

impl QuorumCertificate {
    pub fn genesis(committee_size: usize) -> Self {
        Self {
            signature: NodeSignature::identity(),
            cosigned: bitvec![u8, bitvec::order::Msb0; 1; committee_size],
            block_hash: Hash::ZERO,
            view: 0,
        }
    }

    pub fn new(
        signatures: &[NodeSignature],
        cosigned: BitVec,
        block_hash: Hash,
        view: u64,
    ) -> Self {
        QuorumCertificate {
            signature: NodeSignature::aggregate(signatures).unwrap(),
            cosigned,
            block_hash,
            view,
        }
    }

    // Verifying an aggregated signature is a case of verifying the aggregated public key
    // against the aggregated signature
    pub fn verify(&self, public_keys: Vec<NodePublicKey>) -> bool {
        // Select which public keys have gone into creating the signature
        let public_keys = public_keys
            .into_iter()
            .zip(self.cosigned.iter())
            .filter_map(
                |(public_key, cosigned)| {
                    if *cosigned {
                        Some(public_key)
                    } else {
                        None
                    }
                },
            )
            .collect::<Vec<_>>();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());

        NodeSignature::verify_aggregate(&self.signature, &bytes, public_keys).is_ok()
    }

    pub fn compute_hash(&self) -> Hash {
        Hash::compute([
            &self.signature.to_bytes(),
            &self.cosigned.clone().into_vec(), // FIXME: What does this do when `self.cosigned.len() % 8 != 0`?
            self.block_hash.as_bytes(),
        ])
    }
}

impl Display for QuorumCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "QC hash: {}, ", self.compute_hash())?;
        write!(f, "QC signature: [..], ")?;
        write!(f, "QC cosigned: {:?}, ", self.cosigned)?;
        Ok(())
    }
}

/// A collection of `n - f` [QuorumCertificate]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateQc {
    pub signature: NodeSignature,
    pub cosigned: BitVec,
    pub view: u64,
    pub qcs: Vec<QuorumCertificate>,
}

impl AggregateQc {
    pub fn compute_hash(&self) -> Hash {
        let hashes: Vec<_> = self.qcs.iter().map(|qc| qc.compute_hash()).collect();
        let signers = self.cosigned.as_raw_slice();
        Hash::compute([
            &self.signature.to_bytes(),
            signers,
            Hash::compute(
                hashes
                    .iter()
                    .map(|hash| hash.as_bytes())
                    .collect::<Vec<_>>(),
            )
            .as_bytes(),
        ])
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BlockRef {
    Hash(Hash),
    View(u64),
    Number(u64),
}

/// The [Copy]-able subset of a block.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlockHeader {
    pub view: u64, // only useful to consensus: the proposer can be derived from the block's view
    pub number: u64, // distinct from view, this is the normal incrementing block number
    pub hash: Hash,
    pub parent_hash: Hash,
    pub signature: NodeSignature,
    pub state_root_hash: Hash,
    /// The time this block was mined at.
    pub timestamp: SystemTime,
    pub gas_used: EvmGas,
}

impl BlockHeader {
    pub fn genesis_hash() -> Hash {
        Hash::compute([&0_u64.to_be_bytes(), Hash::ZERO.as_bytes()])
    }

    pub fn genesis(state_root_hash: Hash) -> Self {
        Self {
            view: 0,
            number: 0,
            hash: BlockHeader::genesis_hash(),
            parent_hash: Hash::ZERO,
            signature: NodeSignature::identity(),
            state_root_hash,
            timestamp: SystemTime::UNIX_EPOCH,
            gas_used: EvmGas(0),
        }
    }
}

impl Default for BlockHeader {
    /// Not suitable for use as a real block header.
    fn default() -> Self {
        Self {
            view: 0,
            number: 0,
            hash: Hash::ZERO,
            parent_hash: Hash::ZERO,
            signature: NodeSignature::identity(),
            state_root_hash: Hash(Keccak256::digest([alloy_rlp::EMPTY_STRING_CODE]).into()),
            timestamp: SystemTime::UNIX_EPOCH,
            gas_used: EvmGas(0),
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
    pub fn genesis(state_root_hash: Hash) -> Block {
        let view = 0u64;
        let number = 0u64;
        let qc = QuorumCertificate {
            signature: NodeSignature::identity(),
            cosigned: bitvec![u8, bitvec::order::Msb0; 1; 0],
            block_hash: Hash::ZERO,
            view: 0,
        };
        let parent_hash = Hash::ZERO;
        let timestamp = SystemTime::UNIX_EPOCH;

        let digest = Hash::compute([
            &view.to_be_bytes(),
            &number.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            // hash of agg missing here intentionally
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
        ]);

        Block {
            header: BlockHeader {
                view,
                number,
                hash: digest,
                parent_hash,
                signature: NodeSignature::identity(),
                state_root_hash,
                timestamp,
                gas_used: EvmGas(0),
            },
            qc: QuorumCertificate {
                signature: NodeSignature::identity(),
                cosigned: bitvec![u8, bitvec::order::Msb0; 1; 0],
                block_hash: Hash::ZERO,
                view: 0,
            },
            agg: None,
            transactions: vec![],
        }
    }

    pub fn verify_hash(&self) -> Result<()> {
        let computed_hash = if let Some(agg) = &self.agg {
            Hash::compute([
                &self.view().to_be_bytes(),
                &self.number().to_be_bytes(),
                self.qc.compute_hash().as_bytes(),
                agg.compute_hash().as_bytes(),
                self.parent_hash().as_bytes(),
                self.state_root_hash().as_bytes(),
                &self.gas_used().0.to_be_bytes(),
            ])
        } else {
            Hash::compute([
                &self.view().to_be_bytes(),
                &self.number().to_be_bytes(),
                self.qc.compute_hash().as_bytes(),
                self.parent_hash().as_bytes(),
                self.state_root_hash().as_bytes(),
                &self.gas_used().0.to_be_bytes(),
            ])
        };

        if computed_hash != self.hash() {
            return Err(anyhow!("invalid hash"));
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_qc(
        secret_key: SecretKey,
        view: u64,
        number: u64,
        qc: QuorumCertificate,
        parent_hash: Hash,
        state_root_hash: Hash,
        transactions: Vec<Hash>,
        timestamp: SystemTime,
        gas_used: EvmGas,
    ) -> Block {
        let digest = Hash::compute([
            &view.to_be_bytes(),
            &number.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            // hash of agg missing here intentionally
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
            &gas_used.0.to_be_bytes(),
        ]);
        let signature = secret_key.sign(digest.as_bytes());
        Block {
            header: BlockHeader {
                view,
                number,
                hash: digest,
                parent_hash,
                signature,
                state_root_hash,
                timestamp,
                gas_used,
            },
            qc,
            agg: None,
            transactions,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_agg(
        secret_key: SecretKey,
        view: u64,
        number: u64,
        qc: QuorumCertificate,
        agg: AggregateQc,
        parent_hash: Hash,
        state_root_hash: Hash,
        timestamp: SystemTime,
    ) -> Block {
        let digest = Hash::compute([
            &view.to_be_bytes(),
            &number.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            agg.compute_hash().as_bytes(),
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
            &EvmGas(0).0.to_be_bytes(),
        ]);
        let signature = secret_key.sign(digest.as_bytes());
        Block {
            header: BlockHeader {
                view,
                number,
                hash: digest,
                parent_hash,
                signature,
                state_root_hash,
                timestamp,
                gas_used: EvmGas(0),
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

    pub fn number(&self) -> u64 {
        self.header.number
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

    pub fn gas_used(&self) -> EvmGas {
        self.header.gas_used
    }
}
