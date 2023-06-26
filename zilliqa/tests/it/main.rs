mod consensus;
mod eth;
mod web3;

use std::{
    fmt::Debug,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use eth_trie::MemoryDB;
use ethers::{
    prelude::SignerMiddleware,
    providers::{HttpClientError, JsonRpcClient, JsonRpcError, Provider},
    signers::{LocalWallet, Signer},
};
use futures::{stream::BoxStream, Future, FutureExt, StreamExt};
use itertools::Itertools;
use jsonrpsee::{
    types::{Id, RequestSer, Response, ResponsePayload},
    RpcModule,
};
use k256::ecdsa::SigningKey;
use libp2p::PeerId;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_core::CryptoRng;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use zilliqa::{cfg::Config, crypto::SecretKey, message::Message, node::Node};

fn node<R: Rng + CryptoRng>(
    _rng: &mut R,
    secret_key: SecretKey,
    index: usize,
) -> (
    TestNode,
    BoxStream<'static, (PeerId, Option<PeerId>, Message)>,
) {
    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let message_receiver = UnboundedReceiverStream::new(message_receiver);
    // Augment the `message_receiver` stream to include the sender's `PeerId`.
    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let message_receiver = message_receiver
        .map(move |(dest, message)| (peer_id, dest, message))
        .boxed();
    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    std::mem::forget(reset_timeout_receiver);

    let node = Node::new(
        Config::default(),
        secret_key,
        message_sender,
        reset_timeout_sender,
        MemoryDB::new(true),
    )
    .unwrap();
    let node = Arc::new(Mutex::new(node));
    let rpc_module: RpcModule<Arc<Mutex<Node>>> = zilliqa::api::rpc_module(node.clone());

    (
        TestNode {
            index,
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            secret_key,
            inner: node,
            rpc_module,
        },
        message_receiver,
    )
}

/// A node within a test [Network].
struct TestNode {
    index: usize,
    secret_key: SecretKey,
    peer_id: PeerId,
    inner: Arc<Mutex<Node>>,
    #[allow(dead_code)]
    rpc_module: RpcModule<Arc<Mutex<Node>>>,
}

struct Network<'r> {
    // We keep `nodes` and `receivers` separate so we can independently borrow each half of this struct, while keeping
    // the borrow checker happy.
    nodes: Vec<TestNode>,
    /// A stream of messages from each node. The stream items are a tuple of (source, destination, message).
    /// If the destination is `None`, the message is a broadcast.
    receivers: Vec<BoxStream<'static, (PeerId, Option<PeerId>, Message)>>,
    resend_message: UnboundedSender<(PeerId, Option<PeerId>, Message)>,
    rng: &'r mut ChaCha8Rng,
}

impl<'r> Network<'r> {
    pub fn new(rng: &mut ChaCha8Rng, nodes: usize) -> Network {
        let mut keys: Vec<_> = (0..nodes)
            .map(|_| SecretKey::new_from_rng(rng).unwrap())
            .collect();
        // Sort the keys in the same order as they will occur in the consensus committee. This means node indices line
        // up with indices in the committee, making logs easier to read.
        keys.sort_unstable_by_key(|key| key.to_libp2p_keypair().public().to_peer_id());
        let (nodes, mut receivers): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| node(rng, key, i))
            .unzip();

        for node in &nodes {
            println!("Node {}: {}", node.index, node.peer_id);
        }

        nodes
            .iter()
            .enumerate()
            .cartesian_product(nodes.iter().enumerate())
            .for_each(|((i, n1), (j, n2))| {
                if i != j {
                    let key = n2.secret_key;
                    n1.inner
                        .lock()
                        .unwrap()
                        .add_peer(
                            key.to_libp2p_keypair().public().to_peer_id(),
                            key.node_public_key(),
                        )
                        .unwrap();
                }
            });

        let (resend_message, receive_resend_message) =
            mpsc::unbounded_channel::<(PeerId, Option<PeerId>, Message)>();
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        Network {
            nodes,
            receivers,
            resend_message,
            rng,
        }
    }

    pub async fn tick(&mut self) {
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

        println!(
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

        println!(
            "{}",
            format_message(&self.nodes, source, destination, &message)
        );

        if let Some(destination) = destination {
            let node = self
                .nodes
                .iter()
                .find(|n| n.peer_id == destination)
                .unwrap();
            node.inner
                .lock()
                .unwrap()
                .handle_message(source, message)
                .unwrap();
        } else {
            for node in &self.nodes {
                node.inner
                    .lock()
                    .unwrap()
                    .handle_message(source, message.clone())
                    .unwrap();
            }
        }
    }

    pub async fn run_until(
        &mut self,
        mut condition: impl FnMut(&Network) -> bool,
        mut timeout: usize,
    ) -> Result<()> {
        while !condition(self) {
            if timeout == 0 {
                return Err(anyhow!("condition was still false after {timeout} ticks"));
            }

            self.tick().await;

            timeout -= 1;
        }

        Ok(())
    }

    pub async fn run_until_async<Fut: Future<Output = bool>>(
        &mut self,
        mut condition: impl FnMut(Provider<LocalRpcClient>) -> Fut,
        mut timeout: usize,
    ) -> Result<()> {
        let provider = self.provider(0);
        while !condition(provider.clone()).await {
            if timeout == 0 {
                return Err(anyhow!("condition was still false after {timeout} ticks"));
            }

            self.tick().await;

            timeout -= 1;
        }

        Ok(())
    }

    pub fn node(&self, index: usize) -> MutexGuard<Node> {
        self.nodes[index].inner.lock().unwrap()
    }

    pub fn provider(&self, index: usize) -> Provider<LocalRpcClient> {
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: self.nodes[index].rpc_module.clone(),
        };
        Provider::new(client)
    }

    pub fn random_wallet(
        &mut self,
        index: usize,
    ) -> SignerMiddleware<Provider<LocalRpcClient>, LocalWallet> {
        let wallet: LocalWallet = SigningKey::random(self.rng).into();
        let wallet = wallet.with_chain_id(0x8001u64);
        SignerMiddleware::new(self.provider(index), wallet)
    }
}

fn format_message(
    nodes: &[TestNode],
    source: PeerId,
    destination: Option<PeerId>,
    message: &Message,
) -> String {
    let source_index = nodes.iter().find(|n| n.peer_id == source).unwrap().index;
    if let Some(destination) = destination {
        let destination_index = nodes
            .iter()
            .find(|n| n.peer_id == destination)
            .unwrap()
            .index;
        format!("{source_index} -> {destination_index}: {}", message.name())
    } else {
        format!("{source_index} -> *: {}", message.name())
    }
}

/// A helper macro to deploy a contract. Provide the relative path containing the contract, the name of the contract, a
/// wallet and the network. This will include the contract source in the test binary and compile the contract at
/// runtime.
macro_rules! deploy_contract {
    ($path:expr, $contract:expr, $wallet:ident, $network:ident) => {{
        // Include the contract source directly in the binary.
        let contract_source = include_bytes!($path);

        // Write the contract source to a file, so `solc` can compile it.
        let mut contract_file = tempfile::Builder::new().suffix(".sol").tempfile().unwrap();
        std::io::Write::write_all(&mut contract_file, contract_source).unwrap();

        // Compile the contract.
        let out = ethers::solc::Solc::default()
            .compile_source(contract_file.path())
            .unwrap();
        let contract = out
            .get(contract_file.path().to_str().unwrap(), $contract)
            .unwrap();
        let abi = contract.abi.unwrap().clone();
        let bytecode = contract.bytecode().unwrap().clone();

        // Deploy the contract.
        let factory = DeploymentTxFactory::new(abi, bytecode, $wallet.clone());
        let deployment_tx = factory.deploy(()).unwrap().tx;
        let hash = $wallet
            .send_transaction(deployment_tx, None)
            .await
            .unwrap()
            .tx_hash();

        $network
            .run_until_async(
                |p| async move { p.get_transaction_receipt(hash).await.unwrap().is_some() },
                100,
            )
            .await
            .unwrap();

        hash
    }};
}
pub(crate) use deploy_contract;

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
