mod consensus;
mod eth;
mod native_contracts;
mod persistence;
mod web3;
mod zil;
use async_fn_traits::AsyncFn2;
use ethers::solc::SHANGHAI_SOLC;
use ethers::types::U64;
use futures::Stream;
use std::env;
use std::ops::DerefMut;
use std::pin::Pin;
use zilliqa::cfg::ConsensusConfig;
use zilliqa::cfg::NodeConfig;
use zilliqa::crypto::{Hash, NodePublicKey, SecretKey};
use zilliqa::message::{ExternalMessage, InternalMessage};
use zilliqa::node::Node;
use zilliqa::state::Address;

use std::collections::HashMap;
use std::{
    fmt::Debug,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zilliqa::message::Message;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use ethers::utils::secret_key_to_address;
use ethers::{
    abi::Contract,
    prelude::{CompilerInput, DeploymentTxFactory, EvmVersion, Middleware, SignerMiddleware},
    providers::{HttpClientError, JsonRpcClient, JsonRpcError, Provider},
    signers::LocalWallet,
    types::H256,
};
use futures::{FutureExt, StreamExt};
use jsonrpsee::{
    types::{Id, RequestSer, Response, ResponsePayload},
    RpcModule,
};
use k256::ecdsa::SigningKey;
use libp2p::PeerId;
use primitive_types::H160;
use rand::{seq::SliceRandom, Rng};
use rand_chacha::ChaCha8Rng;
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use tempfile::TempDir;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    Mutex as TokioMutex, MutexGuard as TokioMutexGuard,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;

#[derive(Deserialize)]
struct CombinedJson {
    contracts: HashMap<String, AbiContract>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct AbiContract {
    abi: ethabi::Contract,
}

/// Like BoxStream but with an added Sync bound.
type SyncBoxStream<T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'static>>;

type Wallet = SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>;

/// Used for closures inside Network::run_until_async()
#[derive(Clone, Default)]
pub struct Context {
    index: Option<usize>,
    block_number: Option<U64>,
    hash: Option<H256>,
    wallet: Option<Wallet>,
}

impl Context {
    pub fn index(i: usize) -> Self {
        Self {
            index: Some(i),
            ..Default::default()
        }
    }

    pub fn block_number(block_number: U64) -> Self {
        Self {
            block_number: Some(block_number),
            ..Default::default()
        }
    }

    pub fn wallet_and_hash(wallet: Wallet, hash: H256) -> Self {
        Self {
            hash: Some(hash),
            wallet: Some(wallet),
            ..Default::default()
        }
    }

    pub fn wallet_and_block(wallet: Wallet, block_number: U64) -> Self {
        Self {
            block_number: Some(block_number),
            wallet: Some(wallet),
            ..Default::default()
        }
    }

    pub fn wallet(wallet: Wallet) -> Self {
        Self {
            wallet: Some(wallet),
            ..Default::default()
        }
    }
}

// allowing it because the Result gets unboxed immediately anyway, significantly simplifying the
// type
#[allow(clippy::type_complexity)]
fn node(
    genesis_committee: Vec<(NodePublicKey, PeerId)>,
    genesis_hash: Option<Hash>,
    secret_key: SecretKey,
    index: usize,
    datadir: Option<TempDir>,
    genesis_account: H160,
) -> Result<(TestNode, SyncBoxStream<(PeerId, Option<PeerId>, Message)>)> {
    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let message_receiver = UnboundedReceiverStream::new(message_receiver);
    // Augment the `message_receiver` stream to include the sender's `PeerId`.
    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let message_receiver = message_receiver.map(move |(dest, _, message)| (peer_id, dest, message));
    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    std::mem::forget(reset_timeout_receiver);

    let node = Node::new(
        NodeConfig {
            data_dir: datadir
                .as_ref()
                .map(|d| d.path().to_str().unwrap().to_string()),
            consensus: ConsensusConfig {
                genesis_committee,
                genesis_hash,
                // Give a genesis account 1 billion ZIL.
                genesis_accounts: vec![(
                    Address(genesis_account),
                    1_000_000_000u128
                        .checked_mul(10u128.pow(18))
                        .unwrap()
                        .to_string(),
                )],
                ..Default::default()
            },
            ..Default::default()
        },
        secret_key,
        message_sender,
        reset_timeout_sender,
    )?;
    let node = Arc::new(TokioMutex::new(node));
    let rpc_module: RpcModule<Arc<TokioMutex<Node>>> = zilliqa::api::rpc_module(node.clone());

    Ok((
        TestNode {
            index,
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            secret_key,
            inner: node,
            dir: datadir,
            rpc_module,
        },
        Box::pin(message_receiver),
    ))
}

/// A node within a test [Network].
pub struct TestNode {
    index: usize,
    secret_key: SecretKey,
    peer_id: PeerId,
    rpc_module: RpcModule<Arc<TokioMutex<Node>>>,
    inner: Arc<TokioMutex<Node>>,
    dir: Option<TempDir>,
}

pub struct Network {
    pub genesis_committee: Vec<(NodePublicKey, PeerId)>,
    /// Child shards.
    pub children: HashMap<u64, Network>,
    // We keep `nodes` and `receivers` separate so we can independently borrow each half of this struct, while keeping
    // the borrow checker happy.
    nodes: Vec<TestNode>,
    /// A stream of messages from each node. The stream items are a tuple of (source, destination, message).
    /// If the destination is `None`, the message is a broadcast.
    receivers: Vec<SyncBoxStream<(PeerId, Option<PeerId>, Message)>>,
    resend_message: UnboundedSender<(PeerId, Option<PeerId>, Message)>,
    rng: Arc<Mutex<ChaCha8Rng>>,
    /// The seed input for the node - because rng.get_seed() returns a different, internal
    /// representation
    seed: u64,
    genesis_key: SigningKey,
}

impl Network {
    pub fn new(rng: Arc<Mutex<ChaCha8Rng>>, nodes: usize, seed: u64) -> Network {
        let mut keys: Vec<_> = (0..nodes)
            .map(|_| SecretKey::new_from_rng(rng.lock().unwrap().deref_mut()).unwrap())
            .collect();
        // Sort the keys in the same order as they will occur in the consensus committee. This means node indices line
        // up with indices in the committee, making logs easier to read.
        keys.sort_unstable_by_key(|key| key.to_libp2p_keypair().public().to_peer_id());

        let validator = (
            keys[0].node_public_key(),
            keys[0].to_libp2p_keypair().public().to_peer_id(),
        );
        let genesis_committee = vec![validator];
        let genesis_key = SigningKey::random(rng.lock().unwrap().deref_mut());

        let (nodes, mut receivers): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                node(
                    genesis_committee.clone(),
                    None,
                    key,
                    i,
                    Some(tempfile::tempdir().unwrap()),
                    secret_key_to_address(&genesis_key),
                )
                .unwrap()
            })
            .unzip();

        for node in &nodes {
            trace!(
                "Node {}: {} (dir: {})",
                node.index,
                node.peer_id,
                node.dir.as_ref().unwrap().path().to_string_lossy(),
            );
        }

        let (resend_message, receive_resend_message) =
            mpsc::unbounded_channel::<(PeerId, Option<PeerId>, Message)>();
        let receive_resend_message = Box::pin(UnboundedReceiverStream::new(receive_resend_message));
        receivers.push(receive_resend_message);

        // Pause time so we can control it.
        zilliqa::time::pause_at_epoch();

        for node in &nodes[1..] {
            // Simulate every node broadcasting a `JoinCommittee` message.
            resend_message
                .send((
                    node.peer_id,
                    None,
                    Message::External(ExternalMessage::JoinCommittee(
                        node.secret_key.node_public_key(),
                    )),
                ))
                .unwrap();
        }

        Network {
            genesis_committee,
            nodes,
            receivers,
            resend_message,
            rng,
            seed,
            children: HashMap::new(),
            genesis_key,
        }
    }

    pub async fn add_node(&mut self, genesis: bool) -> usize {
        let secret_key = SecretKey::new_from_rng(self.rng.lock().unwrap().deref_mut()).unwrap();
        let (genesis_committee, genesis_hash) = if genesis {
            (self.genesis_committee.clone(), None)
        } else {
            (
                vec![],
                Some(self.nodes[0].inner.lock().await.get_genesis_hash().unwrap()),
            )
        };
        let (node, receiver) = node(
            genesis_committee,
            genesis_hash,
            secret_key,
            self.nodes.len(),
            None,
            secret_key_to_address(&self.genesis_key),
        )
        .unwrap();

        self.resend_message
            .send((
                node.peer_id,
                None,
                Message::External(ExternalMessage::JoinCommittee(
                    node.secret_key.node_public_key(),
                )),
            ))
            .unwrap();

        info!("Node {}: {}", node.index, node.peer_id);

        let index = node.index;

        self.nodes.push(node);
        self.receivers.push(receiver);

        index
    }

    pub async fn tick(&mut self) {
        // Advance time.
        zilliqa::time::advance(Duration::from_millis(1));

        // Take all the currently ready messages from the stream.
        let mut messages = Vec::new();
        for (_i, receiver) in self.receivers.iter_mut().enumerate() {
            loop {
                // Poll the receiver with `unconstrained` to ensure it won't be pre-empted. This makes sure we always
                // get an item if it has been sent. It does not lead to starvation, because we evaluate the returned
                // future with `.now_or_never()` which instantly returns `None` if the future is not ready.
                match tokio::task::unconstrained(receiver.next()).now_or_never() {
                    Some(Some(message)) => {
                        messages.push(message);
                    }
                    Some(None) => {
                        unreachable!("stream was terminated, this should be impossible");
                    }
                    None => {
                        break;
                    }
                }
            }
        }

        trace!(
            "{} possible messages to send ({:?})",
            messages.len(),
            messages
                .iter()
                .map(|(s, d, m)| format_message(&self.nodes, *s, *d, m))
                .collect::<Vec<_>>()
        );

        if messages.is_empty() {
            return;
        }
        // Pick a random message
        let index = self.rng.lock().unwrap().gen_range(0..messages.len());
        let (source, destination, message) = messages.swap_remove(index);
        // Requeue the other messages
        for message in messages {
            self.resend_message.send(message).unwrap();
        }

        trace!(
            "{}",
            format_message(&self.nodes, source, destination, &message)
        );

        if let Message::Internal(internal_message) = message {
            if let InternalMessage::LaunchShard(network_id) = internal_message {
                if let Some(network) = self.children.get_mut(&network_id) {
                    trace!("Launching shard node for {network_id} - adding new node to shard");
                    network.add_node(true).await;
                } else {
                    info!("Launching node in new shard network {network_id}");
                    self.children
                        .insert(network_id, Network::new(self.rng.clone(), 1, self.seed));
                }
            }
        } else {
            // ExternalMessage
            if let Some(destination) = destination {
                let node = self
                    .nodes
                    .iter()
                    .find(|n| n.peer_id == destination)
                    .unwrap();
                let span = tracing::span!(tracing::Level::INFO, "handle_message", node.index);
                span.in_scope(|| async {
                    node.inner
                        .lock()
                        .await
                        .handle_message(source, message)
                        .unwrap();
                })
                .await;
            } else {
                for node in &self.nodes {
                    let span = tracing::span!(tracing::Level::INFO, "handle_message", node.index);
                    span.in_scope(|| async {
                        node.inner
                            .lock()
                            .await
                            .handle_message(source, message.clone())
                            .unwrap();
                    })
                    .await;
                }
            }
        }
    }

    async fn run_until(
        &mut self,
        mut condition: impl FnMut(&mut Network) -> bool,
        mut timeout: usize,
    ) -> Result<()> {
        let initial_timeout = timeout;

        while !condition(self) {
            if timeout == 0 {
                return Err(anyhow!(
                    "condition was still false after {initial_timeout} ticks"
                ));
            }
            self.tick().await;
            timeout -= 1;
        }

        Ok(())
    }

    pub async fn run_until_async(
        &mut self,
        condition: impl for<'a> AsyncFn2<&'a Network, Context, Output = bool>,
        context: Context,
        mut timeout: usize,
    ) -> Result<()> {
        let initial_timeout = timeout;

        while !condition(self, context.clone()).await {
            if timeout == 0 {
                return Err(anyhow!(
                    "condition was still false after {initial_timeout} ticks"
                ));
            }
            self.tick().await;
            timeout -= 1;
        }

        Ok(())
    }

    pub fn random_index(&self) -> usize {
        self.rng.lock().unwrap().gen_range(0..self.nodes.len())
    }

    pub async fn get_node(&self, index: usize) -> TokioMutexGuard<Node> {
        self.nodes[index].inner.lock().await
    }

    pub fn remove_node(&mut self, idx: usize) -> TestNode {
        self.receivers.remove(idx);
        self.nodes.remove(idx)
    }

    pub async fn node_at(&self, index: usize) -> TokioMutexGuard<Node> {
        self.nodes[index].inner.lock().await
    }

    pub async fn genesis_wallet(&mut self) -> Wallet {
        let wallet: LocalWallet = self.genesis_key.clone().into();

        let node = self
            .nodes
            .choose(self.rng.lock().unwrap().deref_mut())
            .unwrap();
        trace!(index = node.index, "node selected for wallet");
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: node.rpc_module.clone(),
        };
        let provider = Provider::new(client);

        SignerMiddleware::new_with_provider_chain(provider, wallet)
            .await
            .unwrap()
    }

    pub async fn random_wallet(&mut self) -> Wallet {
        let wallet: LocalWallet = SigningKey::random(self.rng.lock().unwrap().deref_mut()).into();

        let node = self
            .nodes
            .choose(self.rng.lock().unwrap().deref_mut())
            .unwrap();
        trace!(index = node.index, "node selected for wallet");
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: node.rpc_module.clone(),
        };
        let provider = Provider::new(client);

        SignerMiddleware::new_with_provider_chain(provider, wallet)
            .await
            .unwrap()
    }
}

fn format_message(
    nodes: &[TestNode],
    source: PeerId,
    destination: Option<PeerId>,
    message: &Message,
) -> String {
    let message = match message {
        Message::External(external_message) => match external_message {
            ExternalMessage::Proposal(proposal) => format!(
                "{} [{}] ({:?})",
                message.name(),
                proposal.header.view,
                proposal
                    .committee
                    .iter()
                    .map(|v| nodes.iter().find(|n| n.peer_id == v.peer_id).unwrap().index)
                    .collect::<Vec<_>>()
            ),
            ExternalMessage::BlockRequest(request) => {
                format!("{} [{:?}]", message.name(), request.0)
            }
            ExternalMessage::BlockResponse(response) => {
                format!("{} [{}]", message.name(), response.block.view())
            }
            _ => message.name().to_owned(),
        },
        #[allow(clippy::match_single_binding)]
        Message::Internal(internal_message) => match internal_message {
            _ => message.name().to_owned(),
        },
    };

    let source_index = nodes.iter().find(|n| n.peer_id == source).unwrap().index;
    if let Some(destination) = destination {
        let destination_index = nodes
            .iter()
            .find(|n| n.peer_id == destination)
            .unwrap()
            .index;
        format!("{source_index} -> {destination_index}: {}", message)
    } else {
        format!("{source_index} -> *: {}", message)
    }
}

const PROJECT_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/");
const EVM_VERSION: EvmVersion = EvmVersion::Shanghai;

async fn deploy_contract(
    path: &str,
    contract: &str,
    wallet: Wallet,
    network: &mut Network,
) -> (H256, Contract) {
    let full_path = format!("{}{}", PROJECT_ROOT, path);

    let contract_source = std::fs::read(&full_path).unwrap_or_else(|e| {
        panic!(
            "failed to read contract source {}: aka {:?}. Error: {}",
            path, full_path, e
        )
    });

    // Write the contract source to a file, so `solc` can compile it.
    let mut contract_file = tempfile::Builder::new().suffix(".sol").tempfile().unwrap();
    std::io::Write::write_all(&mut contract_file, &contract_source).unwrap();

    let sc = ethers::solc::Solc::default();

    let mut compiler_input = CompilerInput::new(contract_file.path()).unwrap();
    let compiler_input = compiler_input.first_mut().unwrap();
    compiler_input.settings.evm_version = Some(EVM_VERSION);

    if let Ok(version) = sc.version() {
        // gets the minimum EvmVersion that is compatible the given EVM_VERSION and version arguments
        if EVM_VERSION.normalize_version(&version) != Some(EVM_VERSION) {
            panic!(
                "solc version {} required, currently set {}",
                SHANGHAI_SOLC, version
            );
        }
    }

    let out = sc
        .compile::<CompilerInput>(compiler_input)
        .unwrap_or_else(|e| {
            panic!("failed to compile contract {}: {}", contract, e);
        });

    // test if your solc can compile with v8.20 (shanghai) with
    // solc --evm-version shanghai zilliqa/tests/it/contracts/Storage.sol
    if out.has_error() {
        panic!("failed to compile contract with error  {:?}", out.errors);
    }

    let contract = out
        .get(contract_file.path().to_str().unwrap(), contract)
        .unwrap();
    let abi = contract.abi.unwrap().clone();
    let bytecode = contract.bytecode().unwrap().clone();

    // Deploy the contract.
    let factory = DeploymentTxFactory::new(abi, bytecode, wallet.clone());
    let deployer = factory.deploy(()).unwrap();
    let abi = deployer.abi().clone();
    {
        let hash = wallet
            .send_transaction(deployer.tx, None)
            .await
            .unwrap()
            .tx_hash();

        network
            .run_until_async(
                test_predicates::got_tx_receipt,
                Context::wallet_and_hash(wallet, hash),
                50,
            )
            .await
            .unwrap();

        (hash, abi)
    }
}

/// An implementation of [JsonRpcClient] which sends requests directly to an [RpcModule], without making any network
/// calls.
#[derive(Debug, Clone)]
pub struct LocalRpcClient {
    id: Arc<AtomicU64>,
    rpc_module: RpcModule<Arc<TokioMutex<Node>>>,
}

#[async_trait]
impl JsonRpcClient for LocalRpcClient {
    type Error = HttpClientError;

    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let next_id = self.id.fetch_add(1, Ordering::SeqCst);
        let request = serde_json::value::to_raw_value(&params).unwrap();
        let payload = RequestSer::owned(Id::Number(next_id), method, Some(request));
        let request = serde_json::to_string(&payload).unwrap();

        let (response, _) = self.rpc_module.raw_json_request(&request, 1).await.unwrap();

        let response: Response<Rc<R>> = serde_json::from_str(&response.result).unwrap();

        let r = match response.payload {
            ResponsePayload::Result(r) => r,
            ResponsePayload::Error(e) => {
                return Err(JsonRpcError {
                    code: e.code() as i64,
                    message: e.message().to_owned(),
                    data: e.data().map(|d| serde_json::to_value(d).unwrap()),
                }
                .into());
            }
        };

        let r = Rc::try_unwrap(r.into_owned()).unwrap_or_else(|_| panic!());

        Ok(r)
    }
}

pub mod test_predicates {
    use super::*;
    pub async fn got_tx_receipt(_: &Network, context: Context) -> bool {
        context
            .wallet
            .unwrap()
            .get_transaction_receipt(context.hash.unwrap())
            .await
            .unwrap()
            .is_some()
    }

    pub async fn wallet_block_above(_: &Network, context: Context) -> bool {
        context.wallet.unwrap().get_block_number().await.unwrap() >= context.block_number.unwrap()
    }

    macro_rules! produced_blocks_named {
        ($n:literal, $name: ident) => {
            async fn $name(network: &Network, context: Context) -> bool {
                network
                    .get_node(context.index.unwrap())
                    .await
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.view())
                    >= $n
            }
        };
    }
    pub(crate) use produced_blocks_named;

    /// Generate a produced_blocks function (with an optional suffix) in the local scope
    /// which checks if a random node in the network has produced n blocks, for some literal n
    macro_rules! produced_blocks {
        ($n:literal) => {
            test_predicates::produced_blocks_named!($n, produced_blocks)
        };
        ($n:literal, $name: ident) => {
            paste::paste! {
                test_predicates::produced_blocks_named!($n, [<produced_blocks_ $name>])
            }
        };
    }
    pub(crate) use produced_blocks;
}
