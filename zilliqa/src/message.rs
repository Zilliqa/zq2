use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
    ops::Range,
    path::Path,
};

use alloy::primitives::{Address, B256, U256};
use anyhow::{Result, anyhow};
use bitvec::{bitarr, order::Msb0};
use itertools::Either;
use libp2p::PeerId;
use revm::context_interface::block::BlobExcessGasAndPrice;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{
    crypto::{BlsSignature, Hash, NodePublicKey, SecretKey},
    precompiles::ViewHistory,
    time::SystemTime,
    transaction::{EvmGas, SignedTransaction, TransactionReceipt, VerifiedTransaction},
    trie_storage::TrieStorage,
};

/// The maximum number of validators in the consensus committee. This is passed to the deposit contract and we expect
/// it to reject deposits which would make the committee larger than this.
pub const MAX_COMMITTEE_SIZE: usize = 256;
pub type BitArray = bitvec::BitArr!(for MAX_COMMITTEE_SIZE, in u8, Msb0);
pub type BitSlice = bitvec::slice::BitSlice<u8, Msb0>;

/// A block proposal. The only difference between this and [Block] is that `transactions` contains the full transaction
/// bodies, rather than just hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub header: BlockHeader,
    pub agg: Option<AggregateQc>,
    pub transactions: Vec<SignedTransaction>,
    pub opaque_transactions: Vec<Hash>,
}

impl Proposal {
    /// Constructs a Proposal from a block and a vector of verified transactions.
    /// ```Arguments```
    ///
    /// * `block`: the Block, including the header and the full list of transaction hashes
    ///   included in the block (and proposal)
    ///
    /// * `full_transactions`: the transactions whose full `Transaction` bodies will be
    ///   included in the proposal. The difference between `block.transactions` and
    ///   `full_transactions` make up the `opaque_transactions` (i.e. transactions only known
    ///   by their hash).
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

    pub fn hash(&self) -> Hash {
        self.header.hash
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
    signature: BlsSignature,
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
    pub fn signature(&self) -> BlsSignature {
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
    pub signature: BlsSignature,
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

/// Each node advertises one or more block strategies. Each strategy signifies a willingness to maintain
/// some group of blocks; when we attempt to fetch a block or block range, we will try to pick a peer that
/// maintains the blocks we are interested in.
///
/// This allows us to compute the blocks a peer is likely to have in its cache before having to be told.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlockStrategy {
    /// "I have these blocks at the moment and I won't drop them until view .."
    /// None == unlimited
    CachedViewRange(Range<u64>, Option<u64>),
    /// Latest N blocks.
    Latest(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct BlockRequest {
    pub from_view: u64,
    pub to_view: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub proposals: Vec<Proposal>,
    pub from_view: u64,
    /// When we send a block response, we may also send data on what blocks we are prepared
    /// to serve.
    pub availability: Option<Vec<BlockStrategy>>,
}

impl fmt::Debug for BlockResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockResponse")
            .field("proposals", &self.proposals)
            .field("from_view", &self.from_view)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBlocksByHeight {
    pub request_at: SystemTime,
    pub from_height: u64,
    pub to_height: u64,
}

/// Used to convey proposal processing internally, to avoid blocking threads for too long.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedProposal {
    // An encoded PeerId
    pub from: PeerId,
    pub block: Proposal,
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
/// Keep this in-sync with the routing in P2pNode::start()
pub enum ExternalMessage {
    Proposal(Proposal),
    Vote(Box<Vote>),
    NewView(Box<NewView>),
    BlockRequest(BlockRequest),
    BlockResponse(BlockResponse),
    ProcessProposal,                   // deprecated since 0.7.0
    NewTransaction(SignedTransaction), // deprecated since 0.9.4
    /// An acknowledgement of the receipt of a message. Note this is only used as a response when the caller doesn't
    /// require any data in the response.
    Acknowledgement,
    /// The following are used for the new sync protocol
    InjectedProposal(InjectedProposal),
    /// 0.6.0
    MetaDataRequest(RequestBlocksByHeight),
    MetaDataResponse, // deprecated since 0.9.0
    MultiBlockRequest(Vec<Hash>),
    MultiBlockResponse(Vec<Proposal>),
    /// 0.7.0
    SyncBlockHeaders(Vec<SyncBlockHeader>),
    /// 0.8.0
    PassiveSyncRequest(RequestBlocksByHash),
    PassiveSyncResponse(Vec<BlockTransactionsReceipts>),
    PassiveSyncResponseLZ(Vec<u8>), // compressed block
    /// 0.9.4
    BatchedTransactions(Vec<SignedTransaction>),
}

impl ExternalMessage {
    pub fn into_proposal(self) -> Option<Proposal> {
        match self {
            ExternalMessage::Proposal(p) => Some(p),
            _ => None,
        }
    }
}

/// Returns a terse, human-readable summary of a message.
impl Display for ExternalMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ExternalMessage::PassiveSyncResponseLZ(r) => {
                write!(f, "PassiveSyncResponseLZ({})", r.len())
            }
            ExternalMessage::PassiveSyncResponse(r) => {
                write!(f, "PassiveSyncResponse({})", r.len())
            }
            ExternalMessage::PassiveSyncRequest(r) => {
                write!(f, "PassiveSyncRequest({})", r.hash)
            }
            ExternalMessage::SyncBlockHeaders(r) => {
                write!(f, "SyncBlockHeaders({})", r.len())
            }
            ExternalMessage::MultiBlockRequest(r) => {
                write!(f, "MultiBlockRequest({})", r.len())
            }
            ExternalMessage::MultiBlockResponse(r) => {
                write!(f, "MultiBlockResponse({})", r.len())
            }
            ExternalMessage::MetaDataRequest(r) => {
                write!(f, "MetaDataRequest({:?})", r.from_height..=r.to_height)
            }
            ExternalMessage::InjectedProposal(p) => {
                write!(f, "InjectedProposal({})", p.block.view())
            }
            ExternalMessage::Proposal(p) => write!(f, "Proposal({})", p.view()),
            ExternalMessage::Vote(v) => write!(f, "Vote({})", v.view),
            ExternalMessage::NewView(n) => write!(f, "NewView({})", n.view),
            ExternalMessage::BlockRequest(r) => {
                write!(f, "BlockRequest({}..={})", r.from_view, r.to_view)
            }
            ExternalMessage::BlockResponse(r) => {
                let mut views = r.proposals.iter().map(|p| p.view());
                let first = views.next();
                let last = views.next_back();
                match (first, last) {
                    (None, None) => write!(f, "BlockResponse([])"),
                    (Some(first), None) => {
                        write!(f, "BlockResponse([{first}])")
                    }
                    (Some(first), Some(last)) => {
                        write!(f, "BlockResponse([{first}, ..., {last}])")
                    }
                    (None, Some(_)) => unreachable!(),
                }
            }
            ExternalMessage::NewTransaction(txn) => match txn.clone().verify() {
                Ok(txn) => {
                    write!(
                        f,
                        "NewTransaction(Hash: {:?}, from: {:?}, nonce: {:?})",
                        txn.hash,
                        txn.signer,
                        txn.tx.nonce()
                    )
                }
                Err(err) => {
                    write!(f, "NewTransaction(Unable to verify txn due to: {err:?})")
                }
            },
            ExternalMessage::BatchedTransactions(txns) => {
                write!(f, "BatchedTransactions(txns_count: {:?})", txns.len())
            }
            ExternalMessage::Acknowledgement => write!(f, "RequestResponse"),
            ExternalMessage::ProcessProposal | ExternalMessage::MetaDataResponse => {
                unimplemented!("deprecated")
            }
        }
    }
}

/// A message intended only for local communication between shard nodes and/or the parent p2p node,
/// but not sent over the network.
#[derive(Debug, Clone)]
pub enum InternalMessage {
    /// Notifies the coordinator process to spawn a node of the given shard
    LaunchShard(u64),
    /// Notifes the destination shard to start bridging from the given source shard
    LaunchLink(u64),
    /// Routes intershard call information between two locally running, bridged, shard processes
    IntershardCall(IntershardCall),
    /// Trigger a checkpoint export of the given block, including the state at its root hash as read
    /// from the given trie
    /// (checkpoint block, transactions, parent block, reference to our trie DB, output path)
    ExportBlockCheckpoint(
        Box<Block>,
        Vec<SignedTransaction>,
        Box<Block>,
        TrieStorage,
        ViewHistory,
        Box<Path>,
    ),
    /// Notify p2p cordinator to subscribe to a particular gossipsub topic
    SubscribeToGossipSubTopic(GossipSubTopic),
    /// Notify p2p cordinator to unsubscribe from a particular gossipsub topic
    UnsubscribeFromGossipSubTopic(GossipSubTopic),
}

#[derive(Debug, Clone)]
pub enum GossipSubTopic {
    /// General topic for all nodes. Includes Proposal messages
    General(u64),
    /// Topic for Validators only. Includes NewView messages
    Validator(u64),
}

/// Returns a terse, human-readable summary of a message.
impl Display for InternalMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InternalMessage::LaunchShard(id) => write!(f, "LaunchShard({id})"),
            InternalMessage::LaunchLink(dest) => write!(f, "LaunchLink({dest})"),
            InternalMessage::IntershardCall(_) => write!(f, "IntershardCall"),
            InternalMessage::ExportBlockCheckpoint(block, ..) => {
                write!(f, "ExportCheckpoint({})", block.number())
            }
            InternalMessage::SubscribeToGossipSubTopic(topic) => {
                write!(f, "SubscribeToGossipSubTopic({topic:?})")
            }
            InternalMessage::UnsubscribeFromGossipSubTopic(topic) => {
                write!(f, "UnsubscribeFromGossipSubTopic({topic:?})")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// An aggregated signature from `n - f` distinct replicas, built by signing a block hash in a specific view.
    pub signature: BlsSignature,
    pub cosigned: BitArray,
    pub block_hash: Hash,
    pub view: u64,
}

impl QuorumCertificate {
    pub fn genesis() -> Self {
        Self {
            signature: BlsSignature::identity(),
            cosigned: bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE],
            block_hash: Hash::ZERO,
            view: 0,
        }
    }

    pub fn new_with_identity(block_hash: Hash, view: u64) -> Self {
        QuorumCertificate {
            signature: BlsSignature::identity(),
            cosigned: bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE],
            block_hash,
            view,
        }
    }

    pub fn new(
        signatures: &[BlsSignature],
        cosigned: BitArray,
        block_hash: Hash,
        view: u64,
    ) -> Self {
        QuorumCertificate {
            signature: BlsSignature::aggregate(signatures).unwrap(),
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
                    if *cosigned { Some(public_key) } else { None }
                },
            )
            .collect::<Vec<_>>();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());

        BlsSignature::verify_aggregate(&self.signature, &bytes, public_keys).is_ok()
    }

    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.signature.to_bytes())
            .with(self.cosigned.as_raw_slice()) // FIXME: What does this do when `self.cosigned.len() % 8 != 0`?
            .with(self.block_hash.as_bytes())
            .with(self.view.to_be_bytes())
            .finalize()
    }

    pub fn size(&self) -> usize {
        self.signature.to_bytes().len()
            + self.cosigned.as_raw_slice().len()
            + self.block_hash.as_bytes().len()
            + std::mem::size_of_val(&self.view)
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateQc {
    pub signature: BlsSignature,
    pub cosigned: BitArray,
    pub view: u64,
    pub qcs: Vec<QuorumCertificate>,
}

impl AggregateQc {
    pub fn compute_hash(&self) -> Hash {
        let hashes: Vec<_> = self.qcs.iter().map(|qc| qc.compute_hash()).collect();

        Hash::builder()
            .with(self.signature.to_bytes())
            .with(self.cosigned.as_raw_slice())
            .with(self.view.to_be_bytes())
            .with_iter(hashes.iter().map(|hash| hash.as_bytes()))
            .finalize()
    }

    pub fn size(&self) -> usize {
        let mut size = 0;
        size += self.signature.to_bytes().len();
        size += self.cosigned.as_raw_slice().len();
        size += std::mem::size_of_val(&self.view);
        for qc in &self.qcs {
            size += qc.size();
        }
        size
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BlockRef {
    Hash(Hash),
    View(u64),
    Number(u64),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SyncBlockHeader {
    pub header: BlockHeader,
    pub size_estimate: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBlocksByHash {
    pub hash: Hash,
    pub count: usize,
    pub request_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTransactionsReceipts {
    pub block: Block,
    pub transaction_receipts: Vec<(SignedTransaction, TransactionReceipt)>,
}
/// The [Copy]-able subset of a block.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub view: u64, // only useful to consensus: the proposer can be derived from the block's view
    pub number: u64, // distinct from view, this is the normal incrementing block number
    pub hash: Hash,
    /// A block's quorum certificate (QC) is proof that more than `2n/3` nodes (out of `n`) have voted for this block.
    /// It also includes a pointer to the parent block.
    pub qc: QuorumCertificate,
    pub signature: BlsSignature,
    pub state_root_hash: Hash,
    pub transactions_root_hash: Hash,
    pub receipts_root_hash: Hash,
    /// The time this block was mined at.
    pub timestamp: SystemTime,
    pub gas_used: EvmGas,
    pub gas_limit: EvmGas,
    // randao_reveal and mix_hash are activated at a fork
    #[serde(default)]
    pub randao_reveal: Option<BlsSignature>,
    #[serde(default)]
    pub mix_hash: Option<Hash>,
}

impl BlockHeader {
    pub fn genesis_hash() -> Hash {
        Hash::builder()
            .with(0_u64.to_be_bytes())
            .with(Hash::ZERO.as_bytes())
            .finalize()
    }

    pub fn genesis(state_root_hash: Hash) -> Self {
        Self {
            view: 0,
            number: 0,
            hash: BlockHeader::genesis_hash(),
            qc: QuorumCertificate::genesis(),
            signature: BlsSignature::identity(),
            state_root_hash,
            transactions_root_hash: Hash::ZERO,
            receipts_root_hash: Hash::ZERO,
            timestamp: SystemTime::UNIX_EPOCH,
            gas_used: EvmGas(0),
            gas_limit: EvmGas(0),
            randao_reveal: Some(BlsSignature::identity()),
            mix_hash: Some(Hash::EMPTY),
        }
    }

    pub fn size(&self) -> usize {
        let mut size = size_of_val(&self.view)
            + size_of_val(&self.number)
            + self.hash.as_bytes().len()
            + self.qc.size()
            + self.signature.to_bytes().len()
            + self.state_root_hash.as_bytes().len()
            + self.transactions_root_hash.as_bytes().len()
            + self.receipts_root_hash.as_bytes().len()
            + size_of_val(&self.timestamp)
            + size_of_val(&self.gas_used)
            + size_of_val(&self.gas_limit);

        if let Some(randao_reveal) = &self.randao_reveal {
            size += randao_reveal.to_bytes().len();
        }
        if let Some(mix_hash) = &self.mix_hash {
            size += mix_hash.as_bytes().len();
        }
        size
    }
}

impl Default for BlockHeader {
    /// Not suitable for use as a real block header.
    fn default() -> Self {
        Self {
            view: 0,
            number: 0,
            hash: Hash::ZERO,
            qc: QuorumCertificate::genesis(),
            signature: BlsSignature::identity(),
            state_root_hash: Hash(Keccak256::digest([alloy::rlp::EMPTY_STRING_CODE]).into()),
            transactions_root_hash: Hash::ZERO,
            receipts_root_hash: Hash::ZERO,
            timestamp: SystemTime::UNIX_EPOCH,
            gas_used: EvmGas(0),
            gas_limit: EvmGas(0),
            randao_reveal: None,
            mix_hash: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    /// The block will include an [AggregateQc] if the previous leader failed, meaning we couldn't construct a QC. When
    /// this is not `None`, `qc` will contain a clone of the highest QC within this [AggregateQc];
    pub agg: Option<AggregateQc>,
    pub transactions: Vec<Hash>,
}

impl Block {
    pub fn genesis(state_root_hash: Hash) -> Block {
        Self::new(
            0u64,
            0u64,
            QuorumCertificate::genesis(),
            None,
            state_root_hash,
            Hash::ZERO,
            Hash::ZERO,
            vec![],
            SystemTime::UNIX_EPOCH,
            EvmGas(0),
            EvmGas(0),
            Either::Right(BlsSignature::identity()),
            Some(BlsSignature::identity()),
            Some(Hash::EMPTY),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_qc(
        secret_key: SecretKey,
        view: u64,
        number: u64,
        qc: QuorumCertificate,
        agg: Option<AggregateQc>,
        state_root_hash: Hash,
        transactions_root_hash: Hash,
        receipts_root_hash: Hash,
        transactions: Vec<Hash>,
        timestamp: SystemTime,
        gas_used: EvmGas,
        gas_limit: EvmGas,
        randao_reveal: Option<BlsSignature>,
        mix_hash: Option<Hash>,
    ) -> Block {
        Self::new(
            view,
            number,
            qc,
            agg,
            state_root_hash,
            transactions_root_hash,
            receipts_root_hash,
            transactions,
            timestamp,
            gas_used,
            gas_limit,
            Either::Left(secret_key),
            randao_reveal,
            mix_hash,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        view: u64,
        number: u64,
        qc: QuorumCertificate,
        agg: Option<AggregateQc>,
        state_root_hash: Hash,
        transactions_root_hash: Hash,
        receipts_root_hash: Hash,
        transactions: Vec<Hash>,
        timestamp: SystemTime,
        gas_used: EvmGas,
        gas_limit: EvmGas,
        secret_key_or_signature: Either<SecretKey, BlsSignature>,
        randao_reveal: Option<BlsSignature>,
        mix_hash: Option<Hash>,
    ) -> Self {
        let block = Block {
            header: BlockHeader {
                view,
                number,
                hash: Hash::ZERO,
                qc,
                signature: BlsSignature::identity(),
                state_root_hash,
                transactions_root_hash,
                receipts_root_hash,
                timestamp,
                gas_used,
                gas_limit,
                randao_reveal,
                mix_hash,
            },
            agg,
            transactions,
        };

        let hash = block.compute_hash();
        let signature = secret_key_or_signature
            .map_left(|key| key.sign(hash.as_bytes()))
            .into_inner();

        Block {
            header: BlockHeader {
                hash,
                signature,
                ..block.header
            },
            ..block
        }
    }

    pub fn verify_hash(&self) -> Result<()> {
        if self.compute_hash() != self.hash() {
            return Err(anyhow!("invalid hash"));
        }

        Ok(())
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

    pub fn is_genesis(&self) -> bool {
        self.number() == 0
    }

    pub fn hash(&self) -> Hash {
        self.header.hash
    }

    pub fn parent_hash(&self) -> Hash {
        self.header.qc.block_hash
    }

    pub fn signature(&self) -> BlsSignature {
        self.header.signature
    }

    pub fn state_root_hash(&self) -> Hash {
        self.header.state_root_hash
    }

    pub fn transactions_root_hash(&self) -> Hash {
        self.header.transactions_root_hash
    }

    pub fn receipts_root_hash(&self) -> Hash {
        self.header.receipts_root_hash
    }
    pub fn timestamp(&self) -> SystemTime {
        self.header.timestamp
    }

    pub fn gas_used(&self) -> EvmGas {
        self.header.gas_used
    }
    pub fn gas_limit(&self) -> EvmGas {
        self.header.gas_limit
    }
    pub fn size(&self) -> usize {
        let mut size = 0;

        // Size of BlockHeader
        size += self.header.size();

        // Size of AggregateQc if present
        if let Some(agg) = &self.agg {
            size += agg.size();
        }

        // Size of transactions
        for tx in &self.transactions {
            size += tx.as_bytes().len();
        }

        size
    }

    pub fn compute_randao_reveal(private_key: &SecretKey, view: u64) -> BlsSignature {
        let to_sign = view.to_be_bytes();
        private_key.sign(&to_sign)
    }

    pub fn compute_randao_mix(parent_block: BlockHeader, randao_reveal: BlsSignature) -> Hash {
        let parent_mix = parent_block.mix_hash.unwrap_or(parent_block.hash).0;
        let randao_reveal_hash = Keccak256::digest(randao_reveal.to_bytes());

        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = parent_mix[i] ^ randao_reveal_hash[i];
        }

        Hash(result)
    }
}

impl Block {
    pub fn compute_hash(&self) -> Hash {
        let mut builder = Hash::builder()
            .with(self.view().to_be_bytes())
            .with(self.number().to_be_bytes())
            .with(self.state_root_hash().as_bytes())
            .with(self.transactions_root_hash().as_bytes())
            .with(self.receipts_root_hash().as_bytes())
            .with(
                self.timestamp()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    .to_be_bytes(),
            )
            .with(self.gas_used().0.to_be_bytes())
            .with(self.gas_limit().0.to_be_bytes())
            .with(self.header.qc.compute_hash().as_bytes())
            .with_optional(
                self.agg
                    .as_ref()
                    .map(|agg| agg.compute_hash().as_bytes().to_vec()),
            )
            .with_iter(self.transactions.iter().map(|hash| hash.as_bytes()));

        if let Some(randao_reveal) = &self.header.randao_reveal {
            builder = builder.with(randao_reveal.to_bytes());
        }
        if let Some(mix_hash) = &self.header.mix_hash {
            builder = builder.with(mix_hash.as_bytes());
        }
        builder.finalize()
    }
}

impl revm_context::Block for Block {
    fn number(&self) -> U256 {
        self.header.number.try_into().unwrap_or_default()
    }

    fn beneficiary(&self) -> Address {
        Address::ZERO
    }

    fn timestamp(&self) -> U256 {
        U256::from(
            self.header
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit().0
    }

    fn basefee(&self) -> u64 {
        0
    }

    fn difficulty(&self) -> U256 {
        U256::ZERO
    }

    fn prevrandao(&self) -> Option<B256> {
        Some(self.header.mix_hash.unwrap_or(Hash::EMPTY).0.into())
    }

    fn blob_excess_gas_and_price(&self) -> Option<BlobExcessGasAndPrice> {
        None
    }
}
