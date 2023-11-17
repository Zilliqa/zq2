mod consensus;
mod eth;
mod native_contracts;
mod persistence;
mod web3;
mod zil;
use ethers::solc::SHANGHAI_SOLC;
use std::env;
use std::ops::DerefMut;
use zilliqa::cfg::ConsensusConfig;
use zilliqa::cfg::NodeConfig;
use zilliqa::crypto::{NodePublicKey, SecretKey};
use zilliqa::message::{ExternalMessage, InternalMessage};
use zilliqa::node::Node;
use zilliqa::state::Address;

extern crate fs_extra;
use fs_extra::dir::*;

use std::collections::HashMap;
use std::{
    fmt::Debug,
    fs,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};
use zilliqa::message::Message;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use ethers::utils::secret_key_to_address;
use ethers::{
    abi::Contract,
    prelude::{CompilerInput, DeploymentTxFactory, EvmVersion, SignerMiddleware},
    providers::{HttpClientError, JsonRpcClient, JsonRpcError, Provider},
    signers::LocalWallet,
    types::H256,
};
use futures::{stream::BoxStream, Future, FutureExt, StreamExt};

use jsonrpsee::{
    types::{Id, RequestSer, Response, ResponsePayload},
    RpcModule,
};
use k256::ecdsa::SigningKey;
use libp2p::PeerId;
use rand::{seq::SliceRandom, Rng};
use rand_chacha::ChaCha8Rng;
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use tempfile::TempDir;
use tokio::sync::mpsc::{self, UnboundedSender};
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
    bin: String,
}

// allowing it because the Result gets unboxed immediately anyway, significantly simplifying the
// type
#[allow(clippy::type_complexity)]
fn node(
    config: NodeConfig,
    secret_key: SecretKey,
    index: usize,
    datadir: Option<TempDir>,
) -> Result<(
    TestNode,
    BoxStream<'static, (PeerId, Option<PeerId>, Message)>,
)> {
    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let message_receiver = UnboundedReceiverStream::new(message_receiver);
    // Augment the `message_receiver` stream to include the sender's `PeerId`.
    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let message_receiver = message_receiver
        .map(move |(dest, _, message)| (peer_id, dest, message))
        .boxed();
    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    std::mem::forget(reset_timeout_receiver);

    let node = Node::new(
        NodeConfig {
            data_dir: datadir
                .as_ref()
                .map(|d| d.path().to_str().unwrap().to_string()),
            ..config
        },
        secret_key,
        message_sender,
        reset_timeout_sender,
    )?;
    let node = Arc::new(Mutex::new(node));
    let rpc_module: RpcModule<Arc<Mutex<Node>>> = zilliqa::api::rpc_module(node.clone());

    Ok((
        TestNode {
            index,
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            secret_key,
            inner: node,
            dir: datadir,
            rpc_module,
        },
        message_receiver,
    ))
}

/// A node within a test [Network].
struct TestNode {
    index: usize,
    secret_key: SecretKey,
    peer_id: PeerId,
    rpc_module: RpcModule<Arc<Mutex<Node>>>,
    inner: Arc<Mutex<Node>>,
    dir: Option<TempDir>,
}

struct Network {
    pub genesis_committee: Vec<(NodePublicKey, PeerId)>,
    /// Child shards.
    pub children: HashMap<u64, Network>,
    pub is_main: bool,
    pub shard_id: u64,
    // We keep `nodes` and `receivers` separate so we can independently borrow each half of this struct, while keeping
    // the borrow checker happy.
    nodes: Vec<TestNode>,
    /// A stream of messages from each node. The stream items are a tuple of (source, destination, message).
    /// If the destination is `None`, the message is a broadcast.
    receivers: Vec<BoxStream<'static, (PeerId, Option<PeerId>, Message)>>,
    resend_message: UnboundedSender<(PeerId, Option<PeerId>, Message)>,
    rng: Arc<Mutex<ChaCha8Rng>>,
    /// The seed input for the node - because rng.get_seed() returns a different, internal
    /// representation
    seed: u64,
    genesis_key: SigningKey,
}

impl Network {
    /// Create a main shard network.
    pub fn new(rng: Arc<Mutex<ChaCha8Rng>>, nodes: usize, seed: u64) -> Network {
        Self::new_shard(rng, nodes, true, NodeConfig::default().eth_chain_id, seed)
    }

    pub fn new_shard(
        rng: Arc<Mutex<ChaCha8Rng>>,
        nodes: usize,
        is_main: bool,
        shard_id: u64,
        seed: u64,
    ) -> Network {
        // Make sure first thing is to pause system time
        zilliqa::time::pause_at_epoch();

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

        let config = NodeConfig {
            eth_chain_id: shard_id,
            consensus: ConsensusConfig {
                genesis_committee: genesis_committee.clone(),
                genesis_hash: None,
                is_main,
                consensus_timeout: Duration::from_secs(1),
                // Give a genesis account 1 billion ZIL.
                genesis_accounts: Self::genesis_accounts(&genesis_key),
                ..Default::default()
            },
            ..Default::default()
        };

        let (nodes, mut receivers): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                node(config.clone(), key, i, Some(tempfile::tempdir().unwrap())).unwrap()
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
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        Network {
            genesis_committee,
            nodes,
            is_main,
            shard_id,
            receivers,
            resend_message,
            rng,
            seed,
            children: HashMap::new(),
            genesis_key,
        }
    }

    fn genesis_accounts(genesis_key: &SigningKey) -> Vec<(Address, String)> {
        vec![(
            Address(secret_key_to_address(genesis_key)),
            1_000_000_000u128
                .checked_mul(10u128.pow(18))
                .unwrap()
                .to_string(),
        )]
    }

    pub fn add_node(&mut self, genesis: bool) -> usize {
        let secret_key = SecretKey::new_from_rng(self.rng.lock().unwrap().deref_mut()).unwrap();
        let (genesis_committee, genesis_hash) = if genesis {
            (self.genesis_committee.clone(), None)
        } else {
            (
                vec![],
                Some(
                    self.nodes[0]
                        .inner
                        .lock()
                        .unwrap()
                        .get_genesis_hash()
                        .unwrap(),
                ),
            )
        };

        let config = NodeConfig {
            eth_chain_id: self.shard_id,
            consensus: ConsensusConfig {
                genesis_committee,
                genesis_hash,
                is_main: self.is_main,
                consensus_timeout: Duration::from_secs(1),
                genesis_accounts: Self::genesis_accounts(&self.genesis_key),
                ..Default::default()
            },
            ..Default::default()
        };
        let (node, receiver) = node(config, secret_key, self.nodes.len(), None).unwrap();

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

    pub fn restart(&mut self) {
        // We copy the data dirs from the original network, and re-use the same private keys.

        // Note: the tempdir object has to be held in the vector or the OS
        // will delete it when it goes out of scope.
        let mut options = CopyOptions::new();
        options.copy_inside = true;

        // Collect the keys from the validators
        let keys = self.nodes.iter().map(|n| n.secret_key).collect::<Vec<_>>();

        let validator = (
            keys[0].node_public_key(),
            keys[0].to_libp2p_keypair().public().to_peer_id(),
        );
        let genesis_committee = vec![validator];

        let (nodes, mut receivers): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                // Copy the persistence over
                let new_data_dir = tempfile::tempdir().unwrap();

                info!("Copying data dir over");

                if let Ok(mut entry) = fs::read_dir(self.nodes[i].dir.as_ref().unwrap().path()) {
                    let entry = entry.next().unwrap().unwrap();
                    info!("Copying {:?} to {:?}", entry, new_data_dir);

                    copy(entry.path(), new_data_dir.path(), &options).unwrap();
                } else {
                    warn!("Failed to copy data dir over");
                }

                let config = NodeConfig {
                    eth_chain_id: self.shard_id,
                    consensus: ConsensusConfig {
                        genesis_committee: genesis_committee.clone(),
                        genesis_hash: None,
                        is_main: self.is_main,
                        consensus_timeout: Duration::from_secs(1),
                        // Give a genesis account 1 billion ZIL.
                        genesis_accounts: Self::genesis_accounts(&self.genesis_key),
                        ..Default::default()
                    },
                    ..Default::default()
                };

                node(config, key, i, Some(new_data_dir)).unwrap()
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
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        self.nodes = nodes;
        self.receivers = receivers;
        self.resend_message = resend_message;

        // Now trigger a timeout in all of the nodes until we see network activity again
        // this could of course spin forever, but the test itself should time out.
        loop {
            for node in &self.nodes {
                if node.inner.lock().unwrap().handle_timeout().unwrap() {
                    return;
                }
                zilliqa::time::advance(Duration::from_millis(500));
            }
        }
    }

    fn collect_messages(&mut self) -> Vec<(PeerId, Option<PeerId>, Message)> {
        let mut messages = vec![];

        // Poll the receiver with `unconstrained` to ensure it won't be pre-empted. This makes sure we always
        // get an item if it has been sent. It does not lead to starvation, because we evaluate the returned
        // future with `.now_or_never()` which instantly returns `None` if the future is not ready.
        for (_i, receiver) in self.receivers.iter_mut().enumerate() {
            loop {
                match tokio::task::unconstrained(receiver.next()).now_or_never() {
                    Some(Some(message)) => {
                        messages.push(message);
                    }
                    Some(None) => {
                        warn!("Stream was unreachable!");
                        unreachable!("stream was terminated, this should be impossible");
                    }
                    None => {
                        break;
                    }
                }
            }
        }
        messages
    }

    // Take all the currently ready messages from the stream,
    // remove N-1 propose messages we see where network size = N and the remaining one is
    // the first node in the vector
    // *** Only perform this when the propose message contains one or more txs.
    pub async fn drop_propose_messages_except_one(&mut self) {
        let mut counter = 0;
        let mut proposals_seen = 0;
        let mut broadcast_handled = false;

        loop {
            // Generate some messages
            self.tick().await;

            counter += 1;

            if counter >= 100 {
                panic!("Possibly looping forever looking for propose messages.");
            }

            let mut messages = self.collect_messages();

            if messages.is_empty() {
                warn!("Messages were empty - advance time faster!");
                zilliqa::time::advance(Duration::from_millis(50));
                continue;
            }

            // filter out all the propose messages, except node 0. If the proposal is a broadcast,
            // repackage it as direct messages to all nodes except node 0.
            let mut removed_items = Vec::new();

            // Remove the matching messages
            messages.retain(|(s, d, m)| {
                if let Message::External(ExternalMessage::Proposal(prop)) = m {
                    if !prop.transactions.is_empty() {
                        removed_items.push((*s, *d, m.clone()));
                        return false;
                    }
                }
                true
            });

            // Handle the removed proposes correctly for both cases of broadcast and single cast
            for (s, d, m) in removed_items {
                // If specifically to a node, only allow node 0
                if let Some(dest) = d {
                    // We actually want to allow this message, put it back into the queue
                    if dest == self.nodes[0].peer_id {
                        messages.push((s, Some(dest), m));
                        continue;
                    }

                    // This counts as it getting dropped
                    proposals_seen += 1;
                } else {
                    // Broadcast seen! Push it back into the queue with specific destination of node 0
                    messages.push((s, Some(self.nodes[0].peer_id), m));

                    broadcast_handled = true;
                    break;
                }
            }

            // All but one allowed through, we can now quit
            if proposals_seen == self.nodes.len() - 1 || broadcast_handled {
                // Now process all available messages to make sure the nodes execute them
                trace!(
                    "Processing all remaining messages of len {}",
                    messages.len()
                );

                for message in messages {
                    self.handle_message(message);
                }

                break;
            }

            // Requeue the other messages
            for message in messages {
                self.resend_message.send(message).unwrap();
            }
        }
    }

    // Drop the first message in each node queue with N% probability per tick
    pub async fn randomly_drop_messages_then_tick(&mut self, failure_rate: f64) {
        if !(0.0..=1.0).contains(&failure_rate) {
            panic!("failure rate is a probability and must be between 0 and 1");
        }

        for (_i, receiver) in self.receivers.iter_mut().enumerate() {
            // Peek at the messages in the queue

            let drop = self.rng.lock().unwrap().gen_bool(failure_rate);
            if drop {
                // Don't really care too much what the reciever has, just pop something off if
                // possible
                match tokio::task::unconstrained(receiver.next()).now_or_never() {
                    Some(None) => {
                        unreachable!("stream was terminated, this should be impossible");
                    }
                    Some(Some(message)) => {
                        info!("***** Randomly dropping message: {:?}", message);
                    }
                    _ => {}
                }
            }
        }

        self.tick().await;
    }

    pub async fn tick(&mut self) {
        // Advance time.
        zilliqa::time::advance(Duration::from_millis(1));

        // Take all the currently ready messages from the stream.
        let mut messages = self.collect_messages();

        trace!(
            "{} possible messages to send ({:?})",
            messages.len(),
            messages
                .iter()
                .map(|(s, d, m)| format_message(&self.nodes, *s, *d, m))
                .collect::<Vec<_>>()
        );

        if messages.is_empty() {
            trace!("Messages were empty - advance time and trigger timeout in all nodes!");
            zilliqa::time::advance(Duration::from_millis(500));

            for (index, node) in self.nodes.iter().enumerate() {
                let span = tracing::span!(tracing::Level::INFO, "handle_timeout", index);

                span.in_scope(|| {
                    node.inner.lock().unwrap().handle_timeout().unwrap();
                });
            }
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

        self.handle_message((source, destination, message))
    }

    fn handle_message(&mut self, message: (PeerId, Option<PeerId>, Message)) {
        if let Message::Internal(internal_message) = message.2 {
            if let InternalMessage::LaunchShard(network_id) = internal_message {
                if let Some(network) = self.children.get_mut(&network_id) {
                    trace!("Launching shard node for {network_id} - adding new node to shard");
                    network.add_node(true);
                } else {
                    info!("Launching node in new shard network {network_id}");
                    self.children.insert(
                        network_id,
                        Network::new_shard(self.rng.clone(), 1, false, network_id, self.seed),
                    );
                }
            }
        } else {
            let nodes: Vec<(usize, &TestNode)> = if let Some(destination) = message.1 {
                vec![self
                    .nodes
                    .iter()
                    .enumerate()
                    .find(|(_, n)| n.peer_id == destination)
                    .unwrap()]
            } else {
                self.nodes.iter().enumerate().collect()
            };

            for (index, node) in nodes.iter() {
                let span = tracing::span!(tracing::Level::INFO, "handle_message", index);
                span.in_scope(|| {
                    if message.1.is_some() {
                        info!(
                            "destination: {}, node being used: {}",
                            message.1.unwrap(),
                            node.inner.lock().unwrap().peer_id()
                        );
                    }
                    node.inner
                        .lock()
                        .unwrap()
                        .handle_message(message.0, message.2.clone())
                        .unwrap();
                });
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

    pub async fn run_until_async<Fut: Future<Output = bool>>(
        &mut self,
        mut condition: impl FnMut() -> Fut,
        mut timeout: usize,
    ) -> Result<()> {
        let initial_timeout = timeout;

        while !condition().await {
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

    pub fn random_index(&mut self) -> usize {
        self.rng.lock().unwrap().gen_range(0..self.nodes.len())
    }

    pub fn get_node(&self, index: usize) -> MutexGuard<Node> {
        self.nodes[index].inner.lock().unwrap()
    }

    pub fn remove_node(&mut self, idx: usize) -> TestNode {
        self.receivers.remove(idx);
        self.nodes.remove(idx)
    }

    pub fn node_at(&mut self, index: usize) -> MutexGuard<Node> {
        self.nodes[index].inner.lock().unwrap()
    }

    pub async fn genesis_wallet(
        &mut self,
    ) -> SignerMiddleware<Provider<LocalRpcClient>, LocalWallet> {
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

    pub async fn random_wallet(
        &mut self,
    ) -> SignerMiddleware<Provider<LocalRpcClient>, LocalWallet> {
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
                proposal.header.number,
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
                format!("{} [{}]", message.name(), response.block.number())
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
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
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
        use ethers::providers::Middleware;

        let hash = wallet
            .send_transaction(deployer.tx, None)
            .await
            .unwrap()
            .tx_hash();

        network
            .run_until_async(
                || async {
                    wallet
                        .get_transaction_receipt(hash)
                        .await
                        .unwrap()
                        .is_some()
                },
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
    rpc_module: RpcModule<Arc<Mutex<Node>>>,
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
