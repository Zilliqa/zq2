use ethers::{
    abi::Tokenize,
    providers::{Middleware, PubsubClient},
};
use primitive_types::U256;
use serde_json::{value::RawValue, Value};
mod consensus;
mod eth;
mod persistence;
mod staking;
mod unreliable;
mod web3;
mod zil;

use std::{
    collections::{HashMap, HashSet},
    env,
    fmt::Debug,
    fs,
    ops::DerefMut,
    pin::Pin,
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
    signers::LocalWallet,
    solc::SHANGHAI_SOLC,
    types::{Bytes, TransactionReceipt, H256, U64},
    utils::secret_key_to_address,
};
use fs_extra::dir::*;
use futures::{stream::BoxStream, Future, FutureExt, Stream, StreamExt};
use itertools::Itertools;
use jsonrpsee::{
    types::{Id, Notification, RequestSer, Response, ResponsePayload},
    RpcModule,
};
use k256::ecdsa::SigningKey;
use libp2p::PeerId;
use rand::{seq::SliceRandom, Rng};
use rand_chacha::ChaCha8Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tempfile::TempDir;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::{ReceiverStream, UnboundedReceiverStream};
use tracing::*;
use zilliqa::{
    cfg::{ConsensusConfig, NodeConfig},
    crypto::{NodePublicKey, SecretKey},
    message::{ExternalMessage, InternalMessage},
    node::Node,
    state::Address,
};

/// (source, destination, message) for both
#[derive(Debug, Clone, Serialize, Deserialize)]
enum AnyMessage {
    External(ExternalMessage),
    Internal(u64, u64, InternalMessage),
}

type Wallet = SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>;

type StreamMessage = (PeerId, Option<PeerId>, AnyMessage);

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
    BoxStream<'static, StreamMessage>,
    BoxStream<'static, StreamMessage>,
)> {
    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let message_receiver = UnboundedReceiverStream::new(message_receiver);
    // Augment the `message_receiver` stream to include the sender's `PeerId`.
    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let message_receiver = message_receiver
        .map(move |(dest, _, message)| (peer_id, dest, AnyMessage::External(message)))
        .boxed();

    let (local_message_sender, local_message_receiver) = mpsc::unbounded_channel();
    let local_message_receiver = UnboundedReceiverStream::new(local_message_receiver);
    // Augment the `message_receiver` stream to include the sender and receiver's `PeerId`.
    let local_message_receiver = local_message_receiver
        .map(move |(src, dest, message)| {
            (
                peer_id,
                Some(peer_id),
                AnyMessage::Internal(src, dest, message),
            )
        })
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
        local_message_sender,
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
        local_message_receiver,
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
    pub genesis_deposits: Vec<(NodePublicKey, String, Address)>,
    /// Child shards.
    pub children: HashMap<u64, Network>,
    pub shard_id: u64,
    // We keep `nodes` and `receivers` separate so we can independently borrow each half of this struct, while keeping
    // the borrow checker happy.
    nodes: Vec<TestNode>,
    // We keep track of a list of disconnected nodes. These nodes will not recieve any messages until they are removed
    // from this list.
    disconnected: HashSet<usize>,
    /// A stream of messages from each node. The stream items are a tuple of (source, destination, message).
    /// If the destination is `None`, the message is a broadcast.
    receivers: Vec<BoxStream<'static, StreamMessage>>,
    resend_message: UnboundedSender<StreamMessage>,
    send_to_parent: Option<UnboundedSender<StreamMessage>>,
    rng: Arc<Mutex<ChaCha8Rng>>,
    /// The seed input for the node - because rng.get_seed() returns a different, internal
    /// representation
    seed: u64,
    pub genesis_key: SigningKey,
    scilla_address: String,
}

impl Network {
    /// Create a main shard network.
    pub fn new(
        rng: Arc<Mutex<ChaCha8Rng>>,
        nodes: usize,
        seed: u64,
        scilla_address: String,
    ) -> Network {
        Self::new_shard(
            rng,
            nodes,
            None,
            NodeConfig::default().eth_chain_id,
            seed,
            None,
            scilla_address,
        )
    }

    pub fn new_shard(
        rng: Arc<Mutex<ChaCha8Rng>>,
        nodes: usize,
        send_to_parent: Option<UnboundedSender<StreamMessage>>,
        shard_id: u64,
        seed: u64,
        keys: Option<Vec<SecretKey>>,
        scilla_address: String,
    ) -> Network {
        let mut keys = keys.unwrap_or_else(|| {
            (0..nodes)
                .map(|_| SecretKey::new_from_rng(rng.lock().unwrap().deref_mut()).unwrap())
                .collect()
        });
        // Sort the keys in the same order as they will occur in the consensus committee. This means node indices line
        // up with indices in the committee, making logs easier to read.
        keys.sort_unstable_by_key(|key| key.to_libp2p_keypair().public().to_peer_id());

        let validator = (
            keys[0].node_public_key(),
            keys[0].to_libp2p_keypair().public().to_peer_id(),
        );
        let genesis_committee = vec![validator];
        let genesis_key = SigningKey::random(rng.lock().unwrap().deref_mut());

        // The initial stake of each node.
        let stake = 32_000_000_000_000_000_000u128;
        let genesis_deposits: Vec<_> = keys
            .iter()
            .map(|k| {
                (
                    k.node_public_key(),
                    stake.to_string(),
                    Address::random_using(rng.lock().unwrap().deref_mut()),
                )
            })
            .collect();

        let config = NodeConfig {
            eth_chain_id: shard_id,
            consensus: ConsensusConfig {
                genesis_committee: genesis_committee.clone(),
                genesis_deposits: genesis_deposits.clone(),
                genesis_hash: None,
                is_main: send_to_parent.is_none(),
                consensus_timeout: Duration::from_secs(1),
                // Give a genesis account 1 billion ZIL.
                genesis_accounts: Self::genesis_accounts(&genesis_key),
                empty_block_timeout: Duration::from_millis(25),
                scilla_address: scilla_address.clone(),
                local_address: "host.docker.internal".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };

        let (nodes, external_receivers, local_receivers): (Vec<_>, Vec<_>, Vec<_>) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                node(config.clone(), key, i, Some(tempfile::tempdir().unwrap())).unwrap()
            })
            .multiunzip();

        let mut receivers: Vec<_> = external_receivers
            .into_iter()
            .chain(local_receivers)
            .collect();

        for node in &nodes {
            trace!(
                "Node {}: {} (dir: {})",
                node.index,
                node.peer_id,
                node.dir.as_ref().unwrap().path().to_string_lossy(),
            );
        }

        let (resend_message, receive_resend_message) = mpsc::unbounded_channel::<StreamMessage>();
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        Network {
            genesis_committee,
            genesis_deposits,
            nodes,
            disconnected: HashSet::new(),
            send_to_parent,
            shard_id,
            receivers,
            resend_message,
            rng,
            seed,
            children: HashMap::new(),
            genesis_key,
            scilla_address,
        }
    }

    fn genesis_accounts(genesis_key: &SigningKey) -> Vec<(Address, String)> {
        vec![(
            secret_key_to_address(genesis_key),
            1_000_000_000u128
                .checked_mul(10u128.pow(18))
                .unwrap()
                .to_string(),
        )]
    }

    pub fn add_node(&mut self, genesis: bool) -> usize {
        let secret_key = SecretKey::new_from_rng(self.rng.lock().unwrap().deref_mut()).unwrap();
        self.add_node_with_key(genesis, secret_key)
    }

    pub fn is_main(&self) -> bool {
        self.send_to_parent.is_none()
    }

    pub fn add_node_with_key(&mut self, genesis: bool, secret_key: SecretKey) -> usize {
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
                genesis_deposits: self.genesis_deposits.clone(),
                genesis_hash,
                is_main: self.is_main(),
                consensus_timeout: Duration::from_secs(1),
                genesis_accounts: Self::genesis_accounts(&self.genesis_key),
                empty_block_timeout: Duration::from_millis(25),
                ..Default::default()
            },
            ..Default::default()
        };
        let (node, receiver, local_receiver) =
            node(config, secret_key, self.nodes.len(), None).unwrap();

        self.resend_message
            .send((
                node.peer_id,
                None,
                AnyMessage::External(ExternalMessage::JoinCommittee(
                    node.secret_key.node_public_key(),
                )),
            ))
            .unwrap();

        info!("Node {}: {}", node.index, node.peer_id);

        let index = node.index;

        self.nodes.push(node);
        self.receivers.push(receiver);
        self.receivers.push(local_receiver);

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

        // The initial stake of each node.
        let stake = 32_000_000_000_000_000_000u128;
        let genesis_deposits: Vec<_> = keys
            .iter()
            .map(|k| {
                (
                    k.node_public_key(),
                    stake.to_string(),
                    Address::random_using(self.rng.lock().unwrap().deref_mut()),
                )
            })
            .collect();

        for nodes in &mut self.nodes {
            nodes.inner.lock().unwrap().db.flush();
        }

        let (nodes, external_receivers, local_receivers): (Vec<_>, Vec<_>, Vec<_>) = keys
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
                        genesis_deposits: genesis_deposits.clone(),
                        genesis_hash: None,
                        is_main: self.is_main(),
                        consensus_timeout: Duration::from_secs(1),
                        // Give a genesis account 1 billion ZIL.
                        genesis_accounts: Self::genesis_accounts(&self.genesis_key),
                        empty_block_timeout: Duration::from_millis(25),
                        ..Default::default()
                    },
                    ..Default::default()
                };

                node(config, key, i, Some(new_data_dir)).unwrap()
            })
            .multiunzip();

        let mut receivers: Vec<_> = external_receivers
            .into_iter()
            .chain(local_receivers)
            .collect();

        for node in &nodes {
            trace!(
                "Node {}: {} (dir: {})",
                node.index,
                node.peer_id,
                node.dir.as_ref().unwrap().path().to_string_lossy(),
            );
        }

        let (resend_message, receive_resend_message) = mpsc::unbounded_channel::<StreamMessage>();
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

    fn collect_messages(&mut self) -> Vec<(PeerId, Option<PeerId>, AnyMessage)> {
        let mut messages = vec![];

        // Poll the receiver with `unconstrained` to ensure it won't be pre-empted. This makes sure we always
        // get an item if it has been sent. It does not lead to starvation, because we evaluate the returned
        // future with `.now_or_never()` which instantly returns `None` if the future is not ready.
        for receiver in self.receivers.iter_mut() {
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

        trace!("Dropping propose messages except one");

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
                if let AnyMessage::External(ExternalMessage::Proposal(prop)) = m {
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

        trace!("Finished dropping propose messages except one");
    }

    // Drop the first message in each node queue with N% probability per tick
    pub async fn randomly_drop_messages_then_tick(&mut self, failure_rate: f64) {
        if !(0.0..=1.0).contains(&failure_rate) {
            panic!("failure rate is a probability and must be between 0 and 1");
        }

        for receiver in self.receivers.iter_mut() {
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
            zilliqa::time::advance(Duration::from_millis(1000));

            for (index, node) in self.nodes.iter().enumerate() {
                let span = tracing::span!(tracing::Level::INFO, "handle_timeout", index);

                span.in_scope(|| {
                    node.inner.lock().unwrap().handle_timeout().unwrap();
                });
            }
            return;
        }

        // Immediately forward any IntershardCall or LaunchLink messages to children - the child network will randomize them
        messages.retain(|m| match m.2 {
            AnyMessage::Internal(_, destination, InternalMessage::IntershardCall(_))
                if self.shard_id != destination =>
            {
                self.handle_message(m.clone());
                false
            }
            AnyMessage::Internal(_, _, InternalMessage::LaunchLink(_)) => {
                self.handle_message(m.clone());
                false
            }
            _ => true,
        });
        // This is rather hacky, but probably the best way to get it working: IFF we're a child
        // network, immediately forward all LaunchShard messages to the parent who will handle them
        if let Some(send_to_parent) = self.send_to_parent.as_ref() {
            messages.retain(|m| {
                if let AnyMessage::Internal(_, _, InternalMessage::LaunchShard(new_network_id)) = m.2 {
                    trace!("Child network {} got LaunchShard({new_network_id}) message; forwarding to parent to handle", self.shard_id);
                    send_to_parent.send(m.clone()).unwrap();
                    return false;
                }
                true
            });
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

    fn handle_message(&mut self, message: (PeerId, Option<PeerId>, AnyMessage)) {
        let (source, destination, ref contents) = message;
        match contents {
            AnyMessage::Internal(source_shard, destination_shard, ref internal_message) => {
                match internal_message {
                    InternalMessage::LaunchShard(new_network_id) => {
                        let secret_key = self.find_node(source).unwrap().1.secret_key;
                        if let Some(child_network) = self.children.get_mut(new_network_id) {
                            if child_network.find_node(source).is_none() {
                                trace!("Launching shard node for {new_network_id} - adding new node to shard");
                                child_network.add_node_with_key(true, secret_key);
                            } else {
                                trace!("Received messaged to launch new node in {new_network_id}, but node {source} already exists in that network");
                            }
                        } else {
                            info!("Launching node in new shard network {new_network_id}");
                            self.children.insert(
                                *new_network_id,
                                Network::new_shard(
                                    self.rng.clone(),
                                    1,
                                    Some(self.resend_message.clone()),
                                    *new_network_id,
                                    self.seed,
                                    Some(vec![secret_key]),
                                    self.scilla_address.clone(),
                                ),
                            );
                        }
                    }
                    InternalMessage::LaunchLink(_) | InternalMessage::IntershardCall(_) => {
                        if *destination_shard == self.shard_id {
                            let destination = destination.expect("Local messages are intended to always have the node's own peerid as destination within in the test harness");
                            let idx_node = self.find_node(destination);
                            if let Some((idx, node)) = idx_node {
                                trace!("Handling intershard message {:?} from shard {}, in node {} of shard {}", internal_message, source_shard, idx, self.shard_id);
                                node.inner
                                    .lock()
                                    .unwrap()
                                    .handle_internal_message(
                                        *source_shard,
                                        internal_message.clone(),
                                    )
                                    .unwrap();
                            } else {
                                warn!(
                                    "Dropping intershard message addressed to node that isn't running that shard!"
                                );
                                trace!(?message);
                            }
                        } else if let Some(network) = self.children.get_mut(destination_shard) {
                            trace!(
                                "Forwarding intershard message from shard {} to subshard {}...",
                                self.shard_id,
                                destination_shard
                            );
                            network.resend_message.send(message).unwrap();
                        } else if let Some(send_to_parent) = self.send_to_parent.as_ref() {
                            trace!("Found intershard message that matches none of our children, forwarding it to our parent so they may hopefully route it...");
                            send_to_parent.send(message).unwrap();
                        } else {
                            warn!("Dropping intershard message for shard that does not exist");
                            trace!(?message);
                        }
                    }
                }
            }
            AnyMessage::External(external_message) => {
                let nodes: Vec<(usize, &TestNode)> = if let Some(destination) = destination {
                    let (index, node) = self
                        .nodes
                        .iter()
                        .enumerate()
                        .find(|(_, n)| n.peer_id == destination)
                        .unwrap();
                    if self.disconnected.contains(&index) {
                        vec![]
                    } else {
                        vec![(index, node)]
                    }
                } else {
                    self.nodes
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| !self.disconnected.contains(index))
                        .collect()
                };
                for (index, node) in nodes.iter() {
                    let span = tracing::span!(tracing::Level::INFO, "handle_message", index);
                    span.in_scope(|| {
                        node.inner
                            .lock()
                            .unwrap()
                            .handle_network_message(source, external_message.clone())
                            .unwrap();
                    });
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

    pub async fn run_until_receipt(
        &mut self,
        wallet: &Wallet,
        hash: H256,
        timeout: usize,
    ) -> TransactionReceipt {
        self.run_until_async(
            || async {
                wallet
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            timeout,
        )
        .await
        .unwrap();
        wallet.get_transaction_receipt(hash).await.unwrap().unwrap()
    }

    pub async fn run_until_block(&mut self, wallet: &Wallet, target_block: U64, timeout: usize) {
        self.run_until_async(
            || async { wallet.get_block_number().await.unwrap() >= target_block },
            timeout,
        )
        .await
        .unwrap();
    }

    pub fn disconnect_node(&mut self, index: usize) {
        self.disconnected.insert(index);
    }

    pub fn connect_node(&mut self, index: usize) {
        self.disconnected.remove(&index);
    }

    pub fn random_index(&mut self) -> usize {
        self.rng.lock().unwrap().gen_range(0..self.nodes.len())
    }

    pub async fn wallet_of_node(
        &mut self,
        index: usize,
    ) -> SignerMiddleware<Provider<LocalRpcClient>, LocalWallet> {
        let key = SigningKey::random(self.rng.lock().unwrap().deref_mut());
        let wallet: LocalWallet = key.into();
        let node = &self.nodes[index];
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: node.rpc_module.clone(),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        };
        let provider = Provider::new(client);

        SignerMiddleware::new_with_provider_chain(provider, wallet)
            .await
            .unwrap()
    }

    /// Returns (index, TestNode)
    fn find_node(&self, peer_id: PeerId) -> Option<(usize, &TestNode)> {
        self.nodes
            .iter()
            .enumerate()
            .find(|(_, n)| n.peer_id == peer_id)
    }

    pub fn get_node(&self, index: usize) -> MutexGuard<Node> {
        self.nodes[index].inner.lock().unwrap()
    }

    pub fn get_node_raw(&self, index: usize) -> &TestNode {
        &self.nodes[index]
    }

    pub fn remove_node(&mut self, idx: usize) -> TestNode {
        let _ = self.receivers.remove(idx);
        self.nodes.remove(idx)
    }

    pub fn node_at(&mut self, index: usize) -> MutexGuard<Node> {
        self.nodes[index].inner.lock().unwrap()
    }

    pub async fn wallet_from_key(&mut self, key: SigningKey) -> Wallet {
        let wallet: LocalWallet = key.into();
        let node = self
            .nodes
            .choose(self.rng.lock().unwrap().deref_mut())
            .unwrap();
        trace!(index = node.index, "node selected for wallet");
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: node.rpc_module.clone(),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        };
        let provider = Provider::new(client);

        SignerMiddleware::new_with_provider_chain(provider, wallet)
            .await
            .unwrap()
    }

    pub async fn genesis_wallet(&mut self) -> Wallet {
        self.wallet_from_key(self.genesis_key.clone()).await
    }

    pub async fn random_wallet(&mut self) -> Wallet {
        let key = SigningKey::random(self.rng.lock().unwrap().deref_mut());
        self.wallet_from_key(key).await
    }
}

fn format_message(
    nodes: &[TestNode],
    source: PeerId,
    destination: Option<PeerId>,
    message: &AnyMessage,
) -> String {
    let message = match message {
        AnyMessage::External(message) => match message {
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
                format!("{} [{}]", message.name(), response.proposal.number())
            }
            _ => message.name().to_owned(),
        },
        #[allow(clippy::match_single_binding)]
        AnyMessage::Internal(_source_shard, _destination_shard, message) => match message {
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

fn compile_contract(path: &str, contract: &str) -> (Contract, Bytes) {
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
    (abi, bytecode)
}

async fn deploy_contract(
    path: &str,
    contract: &str,
    wallet: &Wallet,
    network: &mut Network,
) -> (H256, Contract) {
    deploy_contract_with_args(path, contract, (), wallet, network).await
}

async fn deploy_contract_with_args<T: Tokenize>(
    path: &str,
    contract: &str,
    constructor_args: T,
    wallet: &Wallet,
    network: &mut Network,
) -> (H256, Contract) {
    let (abi, bytecode) = compile_contract(path, contract);

    let factory = DeploymentTxFactory::new(abi, bytecode, wallet.clone());
    let deployer = factory.deploy(constructor_args).unwrap();
    let abi = deployer.abi().clone();
    {
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
                200,
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
    subscriptions: Arc<Mutex<HashMap<u64, mpsc::Receiver<String>>>>,
}

#[async_trait]
impl PubsubClient for LocalRpcClient {
    type NotificationStream = Pin<Box<dyn Stream<Item = Box<RawValue>> + Send + Sync + 'static>>;

    fn subscribe<T: Into<U256>>(&self, id: T) -> Result<Self::NotificationStream, Self::Error> {
        let id: U256 = id.into();
        let rx = self
            .subscriptions
            .lock()
            .unwrap()
            .remove(&id.as_u64())
            .unwrap();
        Ok(Box::pin(ReceiverStream::new(rx).map(|s| {
            serde_json::value::to_raw_value(
                &serde_json::from_str::<Notification<Value>>(&s)
                    .unwrap()
                    .params["result"],
            )
            .unwrap()
        })))
    }

    fn unsubscribe<T: Into<U256>>(&self, id: T) -> Result<(), Self::Error> {
        let id: U256 = id.into();
        self.subscriptions.lock().unwrap().remove(&id.as_u64());
        Ok(())
    }
}

#[async_trait]
impl JsonRpcClient for LocalRpcClient {
    type Error = HttpClientError;

    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        // There are some hacks in here for `eth_subscribe` and `eth_unsubscribe`. `RpcModule` does not let us control
        // the `id_provider` and it produces subscription IDs incompatible with Ethereum clients. Specifically, it
        // produces integers and `ethers-rs` expects hex-encoded integers. Our hacks convert to this encoding.

        let next_id = self.id.fetch_add(1, Ordering::SeqCst);
        let mut params: Value = serde_json::to_value(&params).unwrap();
        if method == "eth_unsubscribe" {
            let id = params.as_array_mut().unwrap().get_mut(0).unwrap();
            let str_id = id.as_str().unwrap().strip_prefix("0x").unwrap();
            *id = u64::from_str_radix(str_id, 16).unwrap().into();
        }
        let payload = RequestSer::owned(
            Id::Number(next_id),
            method,
            Some(serde_json::value::to_raw_value(&params).unwrap()),
        );
        let request = serde_json::to_string(&payload).unwrap();

        let (response, rx) = self
            .rpc_module
            .raw_json_request(&request, 64)
            .await
            .unwrap();

        if method == "eth_subscribe" {
            let sub_response = serde_json::from_str::<Response<u64>>(&response);
            if let Ok(Response {
                payload: ResponsePayload::Success(id),
                ..
            }) = sub_response
            {
                let id = id.into_owned();
                self.subscriptions.lock().unwrap().insert(id, rx);
                let r = serde_json::from_str(&format!("\"{:#x}\"", id)).unwrap();
                return Ok(r);
            }
        }

        let response: Response<Rc<R>> = serde_json::from_str(&response).unwrap();

        let r = match response.payload {
            ResponsePayload::Success(r) => r,
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
