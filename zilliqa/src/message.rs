use std::{
    collections::BTreeSet,
    fmt,
    fmt::{Display, Formatter},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use bitvec::{bitvec, order::Msb0};
use libp2p::PeerId;
use primitive_types::H160;
use serde::{Deserialize, Deserializer, Serialize};
use sha3::{Digest, Keccak256};
use time::{macros::format_description, OffsetDateTime};

use crate::{
    consensus::Validator,
    crypto::{Hash, NodePublicKey, NodeSignature, SecretKey},
    time::SystemTime,
    transaction::SignedTransaction,
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
    pub committee: Committee,
    pub transactions: Vec<SignedTransaction>,
}

impl Proposal {
    pub fn from_parts(block: Block, transactions: Vec<SignedTransaction>) -> Self {
        Proposal {
            header: block.header,
            qc: block.qc,
            agg: block.agg,
            committee: block.committee,
            transactions,
        }
    }
    pub fn into_parts(self) -> (Block, Vec<SignedTransaction>) {
        (
            Block {
                header: self.header,
                qc: self.qc,
                agg: self.agg,
                committee: self.committee,
                transactions: self
                    .transactions
                    .iter()
                    .map(|txn| txn.calculate_hash())
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntershardCall {
    pub source_address: H160,
    pub target_address: Option<H160>,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub calldata: Vec<u8>,
}

/// A message intended to be sent over the network as part of p2p communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExternalMessage {
    Proposal(Proposal),
    Vote(Vote),
    NewView(Box<NewView>),
    BlockRequest(BlockRequest),
    BlockResponse(BlockResponse),
    BlockBatchRequest(BlockBatchRequest),
    BlockBatchResponse(BlockBatchResponse),
    NewTransaction(SignedTransaction),
    RequestResponse,
    JoinCommittee(NodePublicKey),
}

/// A message intended only for local communication between shard nodes and/or the parent p2p node,
/// but not sent over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InternalMessage {
    LaunchShard(u64),
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
            ExternalMessage::JoinCommittee(_) => "JoinCommittee",
        }
    }
}

impl InternalMessage {
    pub fn name(&self) -> &'static str {
        match self {
            InternalMessage::LaunchShard(_) => "LaunchShard",
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
    pub signers: Vec<u16>,
    pub view: u64,
    pub qcs: Vec<QuorumCertificate>,
}

impl AggregateQc {
    pub fn compute_hash(&self) -> Hash {
        let hashes: Vec<_> = self.qcs.iter().map(|qc| qc.compute_hash()).collect();
        Hash::compute([
            &self.signature.to_bytes(),
            &self
                .signers
                .iter()
                .flat_map(|signer| signer.to_be_bytes())
                .collect::<Vec<_>>(),
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
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "View: {}, ", self.view)?;
        write!(f, "Block Number: {}, ", self.number)?;
        write!(f, "Block Hash: {}, ", self.hash)?;
        write!(f, "Parent Hash: {}, ", self.parent_hash)?;
        write!(f, "State Root Hash: {}, ", self.state_root_hash)?;
        write!(
            f,
            "Timestamp: {}, ",
            systemtime_strftime(self.timestamp).unwrap()
        )?;
        Ok(())
    }
}

// Helper function to format SystemTime as a string
// https://stackoverflow.com/questions/45386585
fn systemtime_strftime(timestamp: SystemTime) -> Result<String> {
    let time_since_epoch = timestamp
        .elapsed()
        .map(|d| d.as_nanos() as i128)
        // Handle the case where `timestamp` was before unix epoch.
        .unwrap_or_else(|e| -(e.duration().as_nanos() as i128));
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    Ok(OffsetDateTime::from_unix_timestamp_nanos(time_since_epoch)?.format(&format)?)
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

impl From<u64> for BlockNumber {
    fn from(num: u64) -> Self {
        Self::Number(num)
    }
}

impl<'de> Deserialize<'de> for BlockNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BlockNumber;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a non-negative integer or a string")
            }

            fn visit_u64<E>(self, val: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BlockNumber::Number(val))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
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
// Invariant: The set is non-empty
pub struct Committee(BTreeSet<Validator>);

impl Committee {
    pub fn new(validator: Validator) -> Committee {
        Committee([validator].into_iter().collect())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = Validator> + '_ {
        self.0.iter().copied()
    }

    pub fn get_by_index(&self, index: usize) -> Option<Validator> {
        self.0.iter().nth(index).copied()
    }

    pub fn leader(&self, view: u64) -> Validator {
        *self.0.iter().nth(self.leader_index(view)).unwrap()
    }

    pub fn leader_index(&self, view: u64) -> usize {
        view as usize % self.0.len()
    }

    pub fn total_weight(&self) -> u128 {
        self.0.iter().map(|v| v.weight).sum()
    }

    pub fn add_validators(&mut self, validators: impl IntoIterator<Item = Validator>) {
        self.0.extend(validators);
    }

    pub fn remove_by_peer_id(&mut self, peer_id: PeerId) {
        self.0.retain(|v| v.peer_id != peer_id);
    }

    pub fn public_keys(&self) -> Vec<NodePublicKey> {
        self.0.iter().map(|v| v.public_key).collect()
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
    /// The consensus committee for this block.
    pub committee: Committee,
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Header: {} ", self.header)?;
        write!(f, "QC hash: {}, ", self.qc.block_hash)?;
        if let Some(agg) = &self.agg {
            write!(f, "Agg QC view: {}, ", agg.view)?;
        }
        write!(f, "Transactions: {:?}, ", self.transactions)?;
        write!(
            f,
            "Committee: {:?}, ",
            self.committee
                .0
                .iter()
                .map(|c| c.peer_id)
                .collect::<Vec<_>>()
        )?;
        Ok(())
    }
}

impl Block {
    pub fn genesis(committee: Committee, state_root_hash: Hash) -> Block {
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

        // FIXME: Just concatenating the keys is dumb.
        let committee_keys: Vec<_> = committee
            .0
            .iter()
            .flat_map(|v| v.public_key.as_bytes())
            .collect();

        // Could the hash be all zeroes for genesis perhaps?
        let digest = Hash::compute([
            &view.to_be_bytes(),
            &number.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            // hash of agg missing here intentionally
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
            &committee_keys,
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
            },
            qc: QuorumCertificate {
                signature: NodeSignature::identity(),
                cosigned: bitvec![u8, bitvec::order::Msb0; 1; 0],
                block_hash: Hash::ZERO,
                view: 0,
            },
            agg: None,
            transactions: vec![],
            committee,
        }
    }

    pub fn verify_hash(&self) -> Result<()> {
        // FIXME: Just concatenating the keys is dumb.
        let committee_keys: Vec<_> = self
            .committee
            .0
            .iter()
            .flat_map(|v| v.public_key.as_bytes())
            .collect();

        let computed_hash = if let Some(agg) = &self.agg {
            Hash::compute([
                &self.view().to_be_bytes(),
                &self.number().to_be_bytes(),
                self.qc.compute_hash().as_bytes(),
                agg.compute_hash().as_bytes(),
                self.parent_hash().as_bytes(),
                self.state_root_hash().as_bytes(),
                &committee_keys,
            ])
        } else {
            Hash::compute([
                &self.view().to_be_bytes(),
                &self.number().to_be_bytes(),
                self.qc.compute_hash().as_bytes(),
                self.parent_hash().as_bytes(),
                self.state_root_hash().as_bytes(),
                &committee_keys,
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
        committee: Committee,
    ) -> Block {
        // FIXME: Just concatenating the keys is dumb.
        let committee_keys: Vec<_> = committee
            .0
            .iter()
            .flat_map(|v| v.public_key.as_bytes())
            .collect();

        let digest = Hash::compute([
            &view.to_be_bytes(),
            &number.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            // hash of agg missing here intentionally
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
            &committee_keys,
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
            },
            qc,
            agg: None,
            transactions,
            committee,
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
        committee: Committee,
    ) -> Block {
        // FIXME: Just concatenating the keys is dumb.
        let committee_keys: Vec<_> = committee
            .0
            .iter()
            .flat_map(|v| v.public_key.as_bytes())
            .collect();

        let digest = Hash::compute([
            &view.to_be_bytes(),
            &number.to_be_bytes(),
            qc.compute_hash().as_bytes(),
            agg.compute_hash().as_bytes(),
            parent_hash.as_bytes(),
            state_root_hash.as_bytes(),
            &committee_keys,
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
            },
            qc,
            agg: Some(agg),
            transactions: vec![],
            committee,
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
}
