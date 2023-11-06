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
use zilliqa::crypto::{Hash, NodePublicKey, SecretKey};
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
use primitive_types::H160;
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
                consensus_timeout: Duration::from_secs(1),
                ..Default::default()
            },
            ..Default::default()
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
    /// Save the funded genesis address for use in restarts.
    pub genesis_address: H160,
    /// Child shards.
    pub children: HashMap<u64, Network>,
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
    pub fn new(rng: Arc<Mutex<ChaCha8Rng>>, nodes: usize, seed: u64) -> Network {
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

        // save for later use if we restart
        let genesis_address = secret_key_to_address(&genesis_key);

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
                    genesis_address,
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
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        Network {
            genesis_committee,
            genesis_address,
            nodes,
            receivers,
            resend_message,
            rng,
            seed,
            children: HashMap::new(),
            genesis_key,
        }
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

                node(
                    genesis_committee.clone(),
                    None,
                    key,
                    i,
                    Some(new_data_dir),
                    self.genesis_address,
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
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        self.nodes = nodes;
        self.receivers = receivers;
        self.resend_message = resend_message;

        // Now trigger a timeout in all of the nodes until we see network activity again
        // this could of course spin forever, but the test itself should time out.
        loop {
            for node in &self.nodes {
                if node.inner.lock().unwrap().handle_timeout() {
                    return;
                }
                zilliqa::time::advance(Duration::from_millis(500));
            }
        }
    }

    // Drop the first message in each node queue with N% probability per tick
    pub async fn randomly_drop_messages_then_tick(&mut self, failure_rate: f64) {
        if !(0.0..=1.0).contains(&failure_rate) {
            panic!("failure rate is a probability and must be between 0 and 1");
        }

        for (_i, receiver) in self.receivers.iter_mut().enumerate() {
            let drop = self.rng.lock().unwrap().gen_bool(failure_rate);
            if drop {
                // Don't really care too much what the reciever has, just pop something off if
                // possible
                match tokio::task::unconstrained(receiver.next()).now_or_never() {
                    Some(None) => {
                        unreachable!("stream was terminated, this should be impossible");
                    }
                    Some(Some(message)) => {
                        //messages.push(message);
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
                        warn!("Stream was unreachable!");
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
            trace!("Messages were empty - advance time and trigger timeout in all nodes!");
            zilliqa::time::advance(Duration::from_millis(500));

            for node in &self.nodes {
                node.inner.lock().unwrap().handle_timeout();
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

        if let Message::Internal(internal_message) = message {
            if let InternalMessage::LaunchShard(network_id) = internal_message {
                if let Some(network) = self.children.get_mut(&network_id) {
                    trace!("Launching shard node for {network_id} - adding new node to shard");
                    network.add_node(true);
                } else {
                    info!("Launching node in new shard network {network_id}");
                    self.children
                        .insert(network_id, Network::new(self.rng.clone(), 1, self.seed));
                }
            }
        } else {
            let nodes: Vec<&TestNode> = if let Some(destination) = destination {
                vec![self
                    .nodes
                    .iter()
                    .find(|n| n.peer_id == destination)
                    .unwrap()]
            } else {
                self.nodes.iter().collect()
            };

            for (index, node) in nodes.iter().enumerate() {
                let span = tracing::span!(tracing::Level::INFO, "handle_message", index);
                span.in_scope(|| {
                    node.inner
                        .lock()
                        .unwrap()
                        .handle_message(source, message.clone())
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
