mod consensus;
mod eth;
mod persistence;
mod web3;
use std::env;

use std::{
    fmt::Debug,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use ethers::{
    abi::Contract,
    prelude::{CompilerInput, DeploymentTxFactory, EvmVersion, SignerMiddleware},
    providers::{HttpClientError, JsonRpcClient, JsonRpcError, Provider},
    signers::{LocalWallet, Signer},
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
use serde::{de::DeserializeOwned, Serialize};
use tempfile::TempDir;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;
use zilliqa::{
    cfg::NodeConfig,
    crypto::{NodePublicKey, SecretKey},
    message::{ExternalMessage, Message},
    node::Node,
};

// allowing it because the Result gets unboxed immediately anyway, significantly simplifying the
// type
#[allow(clippy::type_complexity)]
fn node(
    genesis_committee: Vec<(NodePublicKey, PeerId)>,
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
            genesis_committee,
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

struct Network<'r> {
    pub genesis_committee: Vec<(NodePublicKey, PeerId)>,
    // We keep `nodes` and `receivers` separate so we can independently borrow each half of this struct, while keeping
    // the borrow checker happy.
    nodes: Vec<TestNode>,
    /// A stream of messages from each node. The stream items are a tuple of (source, destination, message).
    /// If the destination is `None`, the message is a broadcast.
    receivers: Vec<BoxStream<'static, (PeerId, Option<PeerId>, Message)>>,
    resend_message: UnboundedSender<(PeerId, Option<PeerId>, Message)>,
    rng: &'r mut ChaCha8Rng,
    /// The seed input for the node - because rng.get_seed() returns a different, internal
    /// representation
    seed: u64,
}

impl<'r> Network<'r> {
    pub fn new(rng: &mut ChaCha8Rng, nodes: usize, seed: u64) -> Network {
        let mut keys: Vec<_> = (0..nodes)
            .map(|_| SecretKey::new_from_rng(rng).unwrap())
            .collect();
        // Sort the keys in the same order as they will occur in the consensus committee. This means node indices line
        // up with indices in the committee, making logs easier to read.
        keys.sort_unstable_by_key(|key| key.to_libp2p_keypair().public().to_peer_id());

        let validator = (
            keys[0].node_public_key(),
            keys[0].to_libp2p_keypair().public().to_peer_id(),
        );
        let genesis_committee = vec![validator];

        let (nodes, mut receivers): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                node(
                    genesis_committee.clone(),
                    key,
                    i,
                    Some(tempfile::tempdir().unwrap()),
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
        }
    }

    pub fn add_node(&mut self) -> usize {
        let secret_key = SecretKey::new_from_rng(self.rng).unwrap();
        let (node, receiver) = node(
            self.genesis_committee.clone(),
            secret_key,
            self.nodes.len(),
            None,
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
        let index = self.rng.gen_range(0..messages.len());
        let (source, destination, message) = messages.swap_remove(index);
        // Requeue the other messages
        for message in messages {
            self.resend_message.send(message).unwrap();
        }

        trace!(
            "{}",
            format_message(&self.nodes, source, destination, &message)
        );

        if let Some(destination) = destination {
            let node = self
                .nodes
                .iter()
                .find(|n| n.peer_id == destination)
                .unwrap();
            let span = tracing::span!(tracing::Level::INFO, "handle_message", node.index);
            span.in_scope(|| {
                node.inner
                    .lock()
                    .unwrap()
                    .handle_message(source, message)
                    .unwrap();
            });
        } else {
            for node in &self.nodes {
                let span = tracing::span!(tracing::Level::INFO, "handle_message", node.index);
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

    pub async fn run_until(
        &mut self,
        condition: impl FnMut(&mut Network) -> bool,
        timeout: usize,
    ) -> Result<()> {
        self.run_until_rec(condition, timeout, timeout).await
    }

    async fn run_until_rec(
        &mut self,
        mut condition: impl FnMut(&mut Network) -> bool,
        mut timeout: usize,
        orig_timeout: usize,
    ) -> Result<()> {
        while !condition(self) {
            if timeout == 0 {
                return Err(anyhow!(
                    "condition was still false after {orig_timeout} ticks"
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
        while !condition().await {
            if timeout == 0 {
                return Err(anyhow!("condition was still false after {timeout} ticks"));
            }

            self.tick().await;

            timeout -= 1;
        }

        Ok(())
    }

    pub fn random_index(&mut self) -> usize {
        self.rng.gen_range(0..self.nodes.len())
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

    pub fn genesis_wallet(&mut self) -> SignerMiddleware<Provider<LocalRpcClient>, LocalWallet> {
        // Private key with funds should be at 0x00....01
        let hex_string = "0000000000000000000000000000000000000000000000000000000000000001";
        let hex_bytes = hex::decode(hex_string).expect("Failed to decode hex");

        let wallet: LocalWallet = SigningKey::from_slice(hex_bytes.as_slice()).unwrap().into();
        let wallet = wallet.with_chain_id(0x8001u64);

        let node = self.nodes.choose(self.rng).unwrap();
        trace!(index = node.index, "node selected for wallet");
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: node.rpc_module.clone(),
        };
        let provider = Provider::new(client);

        SignerMiddleware::new(provider, wallet)
    }

    pub fn random_wallet(&mut self) -> SignerMiddleware<Provider<LocalRpcClient>, LocalWallet> {
        let wallet: LocalWallet = SigningKey::random(self.rng).into();
        let wallet = wallet.with_chain_id(0x8001u64);

        let node = self.nodes.choose(self.rng).unwrap();
        trace!(index = node.index, "node selected for wallet");
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: node.rpc_module.clone(),
        };
        let provider = Provider::new(client);

        SignerMiddleware::new(provider, wallet)
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

async fn deploy_contract(
    path: &str,
    contract: &str,
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    network: &mut Network<'_>,
) -> (H256, Contract) {
    // Include the contract source directly in the binary.
    //let contract_source = include_bytes!(path.to_string());

    let mut full_path = env::current_dir().unwrap();
    full_path.push(path);

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
    compiler_input.settings.evm_version = Some(EvmVersion::Shanghai);

    let out = sc
        .compile::<CompilerInput>(compiler_input)
        .unwrap_or_else(|e| {
            panic!("failed to compile contract {}: {}", contract, e.to_string());
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
