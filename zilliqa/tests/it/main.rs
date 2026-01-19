use alloy::{
    json_abi::JsonAbi as Contract,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes, TxHash, U256},
    providers::{
        Identity,
        Provider,
        ProviderBuilder,
        RootProvider,
        WalletProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        // mock::Asserter,
    },
    pubsub::{ConnectionHandle, ConnectionInterface, PubSubConnect},
    rpc::{
        client::RpcClient,
        json_rpc::{RequestPacket, Response, ResponsePacket, SerializedRequest},
        types::{TransactionInput, TransactionReceipt, TransactionRequest},
    },
    signers::{local::PrivateKeySigner, utils::secret_key_to_address},
    transports::{BoxTransport, TransportConnect, TransportError, TransportFut, TransportResult},
};
use alloy::{
    rpc::json_rpc::{PubSubItem, ResponsePayload},
    transports::utils::Spawnable,
};
use arc_swap::ArcSwap;
use ethabi::Token;
use jsonrpsee::types::Request;
use serde_json::value::{RawValue, Value};
use tower::Service;
use zilliqa::{
    cfg::{ApiLimits, DbConfig, max_missed_view_age_default, new_view_broadcast_interval_default},
    contracts,
    crypto::NodePublicKey,
    db::BlockFilter,
    state::contract_addr,
};
mod admin;
mod consensus;
mod debug;
mod eth;
mod ots;
mod penalty;
mod persistence;
mod staking;
mod sync;
mod trace;
mod txpool;
mod unreliable;
mod web3;
mod zil;

use std::{
    collections::{HashMap, HashSet},
    env,
    fmt::Debug,
    ops::DerefMut,
    path::Path,
    sync::{Arc, Mutex, atomic::AtomicUsize},
    time::Duration,
};

use anyhow::{Result, anyhow};
use foundry_compilers::{
    artifacts::{EvmVersion, SolcInput, Source},
    solc::{Solc, SolcLanguage},
};
use fs_extra::dir::*;
use futures::{Future, FutureExt, StreamExt, stream::BoxStream};
use itertools::Itertools;
use jsonrpsee::RpcModule;
use k256::ecdsa::SigningKey;
use libp2p::PeerId;
use rand::{Rng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;
use tempfile::TempDir;
use tokio::{
    select,
    sync::mpsc::{self, UnboundedSender},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;
use zilliqa::{
    api,
    cfg::{
        Amount, ApiServer, Checkpoint, ConsensusConfig, ContractUpgradeConfig, ContractUpgrades,
        Fork, GenesisDeposit, NodeConfig, ReinitialiseParams, SyncConfig,
        allowed_timestamp_skew_default, block_request_batch_size_default,
        block_request_limit_default, consensus_timeout_default, eth_chain_id_default,
        failed_request_sleep_duration_default, genesis_fork_default, max_blocks_in_flight_default,
        scilla_ext_libs_path_default, state_cache_size_default, total_native_token_supply_default,
        u64_max,
    },
    crypto::{SecretKey, TransactionPublicKey},
    db,
    message::{ExternalMessage, InternalMessage},
    node::{Node, RequestId},
    node_launcher::ResponseChannel,
    sync::SyncPeers,
    transaction::EvmGas,
};

/// Helper struct for network.add_node()
#[derive(Default)]
pub struct NewNodeOptions {
    secret_key: Option<SecretKey>,
    onchain_key: Option<SigningKey>,
    checkpoint: Option<Checkpoint>,
    prune_interval: Option<u64>,
    base_height: Option<u64>,
    state_sync: Option<bool>,
}

impl NewNodeOptions {
    fn secret_key_or_random(&self, rng: Arc<Mutex<ChaCha8Rng>>) -> SecretKey {
        self.secret_key
            .unwrap_or_else(|| SecretKey::new_from_rng(rng.lock().unwrap().deref_mut()).unwrap())
    }

    fn onchain_key_or_random(&self, rng: Arc<Mutex<ChaCha8Rng>>) -> SigningKey {
        self.onchain_key
            .clone()
            .unwrap_or_else(|| k256::ecdsa::SigningKey::random(rng.lock().unwrap().deref_mut()))
    }
}

/// (source, destination, message) for both
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum AnyMessage {
    External(ExternalMessage),
    Internal(u64, u64, InternalMessage),
    Response {
        channel: ResponseChannel,
        message: ExternalMessage,
    },
}
type Wallet = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

type StreamMessage = (PeerId, Option<(PeerId, RequestId)>, AnyMessage);

// allowing it because the Result gets unboxed immediately anyway, significantly simplifying the
// type
#[allow(clippy::type_complexity)]
fn node(
    config: NodeConfig,
    secret_key: SecretKey,
    onchain_key: SigningKey,
    index: usize,
    datadir: Option<TempDir>,
) -> Result<(
    TestNode,
    BoxStream<'static, StreamMessage>,
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
                Some((peer_id, RequestId::default())),
                AnyMessage::Internal(src, dest, message),
            )
        })
        .boxed();

    let (request_responses_sender, request_responses_receiver) = mpsc::unbounded_channel();
    let request_responses_receiver =
        UnboundedReceiverStream::new(request_responses_receiver).boxed();
    let request_responses_receiver = request_responses_receiver
        // A bit of a hack here - We keep the destination of responses as `None` for now (as if they were a broadcast)
        // and look up the destination via the channel later.
        .map(move |(channel, message)| (peer_id, None, AnyMessage::Response { channel, message }))
        .boxed();

    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    std::mem::forget(reset_timeout_receiver);

    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let sync_peers = Arc::new(SyncPeers::new(peer_id));
    let swarm_peers = Arc::new(ArcSwap::from_pointee(Vec::new()));

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
        request_responses_sender,
        reset_timeout_sender,
        Arc::new(AtomicUsize::new(0)),
        sync_peers.clone(),
        swarm_peers,
    )?;
    let node = Arc::new(node);
    let rpc_module = api::rpc_module(node.clone(), &api::all_enabled());

    Ok((
        TestNode {
            index,
            peer_id,
            secret_key,
            onchain_key,
            inner: node,
            dir: datadir,
            rpc_module,
            peers: sync_peers,
        },
        message_receiver,
        local_message_receiver,
        request_responses_receiver,
    ))
}

/// A node within a test [Network].
struct TestNode {
    index: usize,
    secret_key: SecretKey,
    onchain_key: SigningKey,
    peer_id: PeerId,
    rpc_module: RpcModule<Arc<Node>>,
    inner: Arc<Node>,
    dir: Option<TempDir>,
    peers: Arc<SyncPeers>,
}

struct Network {
    pub genesis_deposits: Vec<GenesisDeposit>,
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
    /// When we send a request to a node, we also send it a [ResponseChannel]. The node sends a response to that
    /// request by passing the [ResponseChannel] back to us. This map lets us remember who to send that response to,
    /// based on who the initial request was from.
    pending_responses: HashMap<ResponseChannel, PeerId>,
    /// Counter for the next unassigned response channel ID. Starts at 0 and increments with each request.
    response_channel_id: u64,
    resend_message: UnboundedSender<StreamMessage>,
    send_to_parent: Option<UnboundedSender<StreamMessage>>,
    rng: Arc<Mutex<ChaCha8Rng>>,
    /// The seed input for the node - because rng.get_seed() returns a different, internal
    /// representation
    seed: u64,
    pub genesis_key: SigningKey,
    scilla_address: String,
    scilla_stdlib_dir: String,
    do_checkpoints: bool,
    blocks_per_epoch: u64,
    deposit_v3_upgrade_block_height: Option<u64>,
    scilla_server_socket_directory: String,
}

impl Network {
    // This is only used in the zilliqa_macros::test macro. Consider refactoring this to a builder
    // or removing entirely (and calling new_shard there)?
    /// Create a main shard network with reasonable defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: Arc<Mutex<ChaCha8Rng>>,
        nodes: usize,
        seed: u64,
        scilla_address: String,
        scilla_stdlib_dir: String,
        do_checkpoints: bool,
        blocks_per_epoch: u64,
        deposit_v3_upgrade_block_height: Option<u64>,
        scilla_server_socket_directory: String,
    ) -> Network {
        Self::new_shard(
            rng,
            nodes,
            None,
            eth_chain_id_default(),
            seed,
            None,
            scilla_address,
            scilla_stdlib_dir,
            do_checkpoints,
            blocks_per_epoch,
            deposit_v3_upgrade_block_height,
            scilla_server_socket_directory,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_shard(
        rng: Arc<Mutex<ChaCha8Rng>>,
        nodes: usize,
        send_to_parent: Option<UnboundedSender<StreamMessage>>,
        shard_id: u64,
        seed: u64,
        keys: Option<Vec<SecretKey>>,
        scilla_address: String,
        scilla_stdlib_dir: String,
        do_checkpoints: bool,
        blocks_per_epoch: u64,
        deposit_v3_upgrade_block_height: Option<u64>,
        scilla_server_socket_directory: String,
    ) -> Network {
        let mut signing_keys = keys.unwrap_or_else(|| {
            (0..nodes)
                .map(|_| SecretKey::new_from_rng(rng.lock().unwrap().deref_mut()).unwrap())
                .collect()
        });
        // Sort the keys in the same order as they will occur in the consensus committee. This means node indices line
        // up with indices in the committee, making logs easier to read.
        signing_keys.sort_unstable_by_key(|key| key.to_libp2p_keypair().public().to_peer_id());

        let onchain_keys: Vec<_> = (0..nodes)
            .map(|_| k256::ecdsa::SigningKey::random(rng.lock().unwrap().deref_mut()))
            .collect();

        let keys: Vec<(_, _)> = signing_keys.into_iter().zip(onchain_keys).collect();

        let genesis_key = SigningKey::random(rng.lock().unwrap().deref_mut());

        // The initial stake of each node.
        let stake = 32_000_000_000_000_000_000u128;
        let genesis_deposits: Vec<_> = keys
            .iter()
            .map(|k| GenesisDeposit {
                public_key: k.0.node_public_key(),
                peer_id: k.0.to_libp2p_keypair().public().to_peer_id(),
                stake: stake.into(),
                reward_address: TransactionPublicKey::Ecdsa(*k.1.verifying_key(), true).into_addr(),
                control_address: TransactionPublicKey::Ecdsa(*k.1.verifying_key(), true)
                    .into_addr(),
            })
            .collect();

        let contract_upgrades = {
            if let Some(deposit_v3_upgrade_block_height_value) = deposit_v3_upgrade_block_height {
                ContractUpgrades::new(
                    Some(ContractUpgradeConfig::from_height(
                        deposit_v3_upgrade_block_height_value,
                    )),
                    None,
                    Some(ContractUpgradeConfig {
                        height: deposit_v3_upgrade_block_height_value,
                        reinitialise_params: Some(ReinitialiseParams::default()),
                    }),
                    Some(ContractUpgradeConfig::from_height(
                        deposit_v3_upgrade_block_height_value,
                    )),
                    Some(ContractUpgradeConfig {
                        height: deposit_v3_upgrade_block_height_value,
                        reinitialise_params: Some(ReinitialiseParams::default()),
                    }),
                    Some(ContractUpgradeConfig::from_height(0)),
                )
            } else {
                ContractUpgrades::new(
                    None,
                    None,
                    Some(ContractUpgradeConfig {
                        height: 0,
                        reinitialise_params: Some(ReinitialiseParams::default()),
                    }),
                    Some(ContractUpgradeConfig::from_height(0)),
                    Some(ContractUpgradeConfig {
                        height: 0,
                        reinitialise_params: Some(ReinitialiseParams::default()),
                    }),
                    Some(ContractUpgradeConfig::from_height(0)),
                )
            }
        };

        let config = NodeConfig {
            eth_chain_id: shard_id,
            consensus: ConsensusConfig {
                genesis_deposits: genesis_deposits.clone(),
                is_main: send_to_parent.is_none(),
                consensus_timeout: consensus_timeout_default(),
                // Give a genesis account 1 billion ZIL.
                genesis_accounts: Self::genesis_accounts(&genesis_key),
                block_time: Duration::from_millis(25),
                scilla_address: scilla_address.clone(),
                scilla_stdlib_dir: scilla_stdlib_dir.clone(),
                scilla_ext_libs_path: scilla_ext_libs_path_default(),
                scilla_server_socket_directory: scilla_server_socket_directory.clone(),
                rewards_per_hour: 204_000_000_000_000_000_000_000u128.into(),
                blocks_per_hour: 3600 * 40,
                minimum_stake: 32_000_000_000_000_000_000u128.into(),
                eth_block_gas_limit: EvmGas(84000000),
                gas_price: 4_761_904_800_000u128.into(),
                main_shard_id: None,
                blocks_per_epoch,
                epochs_per_checkpoint: 1,
                total_native_token_supply: total_native_token_supply_default(),
                contract_upgrades,
                forks: vec![],
                genesis_fork: Fork {
                    scilla_call_gas_exempt_addrs: vec![
                        // Allow the *third* contract deployed by the genesis key to call `scilla_call` for free.
                        secret_key_to_address(&genesis_key).create(2),
                    ],
                    ..genesis_fork_default()
                },
                new_view_broadcast_interval: new_view_broadcast_interval_default(),
            },
            api_servers: vec![ApiServer {
                port: 4201,
                enabled_apis: api::all_enabled(),
                default_quota: None,
            }],
            credit_rates: HashMap::new(),
            allowed_timestamp_skew: allowed_timestamp_skew_default(),
            data_dir: None,
            state_cache_size: state_cache_size_default(),
            load_checkpoint: None,
            do_checkpoints,
            block_request_limit: block_request_limit_default(),
            sync: SyncConfig::default(),
            db: DbConfig::default(),
            failed_request_sleep_duration: failed_request_sleep_duration_default(),
            enable_ots_indices: true,
            max_missed_view_age: max_missed_view_age_default(),
            api_limits: ApiLimits::default(),
        };

        let (nodes, external_receivers, local_receivers, request_response_receivers): (
            Vec<_>,
            Vec<_>,
            Vec<_>,
            Vec<_>,
        ) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                node(
                    config.clone(),
                    key.0,
                    key.1,
                    i,
                    Some(tempfile::tempdir().unwrap()),
                )
                .unwrap()
            })
            .multiunzip();

        let mut receivers: Vec<_> = external_receivers
            .into_iter()
            .chain(local_receivers)
            .chain(request_response_receivers)
            .collect();

        let (resend_message, receive_resend_message) = mpsc::unbounded_channel::<StreamMessage>();
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        let mut peers = nodes.iter().map(|n| n.peer_id).collect_vec();
        peers.shuffle(rng.lock().unwrap().deref_mut());

        for node in &nodes {
            trace!(
                "Node {}: {} (dir: {})",
                node.index,
                node.peer_id,
                node.dir.as_ref().unwrap().path().to_string_lossy(),
            );
            node.peers.add_peers(peers.clone());
        }

        Network {
            genesis_deposits,
            nodes,
            disconnected: HashSet::new(),
            send_to_parent,
            shard_id,
            receivers,
            pending_responses: HashMap::new(),
            response_channel_id: 0,
            resend_message,
            rng,
            seed,
            children: HashMap::new(),
            genesis_key,
            scilla_address,
            do_checkpoints,
            blocks_per_epoch,
            scilla_stdlib_dir,
            deposit_v3_upgrade_block_height,
            scilla_server_socket_directory,
        }
    }

    fn genesis_accounts(genesis_key: &SigningKey) -> Vec<(Address, Amount)> {
        vec![(
            secret_key_to_address(genesis_key),
            1_000_000_000u128
                .checked_mul(10u128.pow(18))
                .unwrap()
                .into(),
        )]
    }

    pub fn is_main(&self) -> bool {
        self.send_to_parent.is_none()
    }

    pub fn add_node(&mut self) -> usize {
        self.add_node_with_options(Default::default())
    }

    pub fn add_node_with_options(&mut self, options: NewNodeOptions) -> usize {
        let contract_upgrades = if self.deposit_v3_upgrade_block_height.is_some() {
            ContractUpgrades::new(
                Some(ContractUpgradeConfig::from_height(
                    self.deposit_v3_upgrade_block_height.unwrap(),
                )),
                None,
                Some(ContractUpgradeConfig {
                    height: self.deposit_v3_upgrade_block_height.unwrap(),
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
                Some(ContractUpgradeConfig::from_height(
                    self.deposit_v3_upgrade_block_height.unwrap(),
                )),
                Some(ContractUpgradeConfig {
                    height: self.deposit_v3_upgrade_block_height.unwrap(),
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
                Some(ContractUpgradeConfig {
                    height: self.deposit_v3_upgrade_block_height.unwrap(),
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
            )
        } else {
            ContractUpgrades::new(
                None,
                None,
                Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
                Some(ContractUpgradeConfig::from_height(0)),
                Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
                Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
            )
        };
        let config = NodeConfig {
            eth_chain_id: self.shard_id,
            api_servers: vec![ApiServer {
                port: 4201,
                enabled_apis: api::all_enabled(),
                default_quota: None,
            }],
            credit_rates: HashMap::new(),
            allowed_timestamp_skew: allowed_timestamp_skew_default(),
            data_dir: None,
            state_cache_size: state_cache_size_default(),
            load_checkpoint: options.checkpoint.clone(),
            do_checkpoints: self.do_checkpoints,
            consensus: ConsensusConfig {
                genesis_deposits: self.genesis_deposits.clone(),
                is_main: self.is_main(),
                consensus_timeout: consensus_timeout_default(),
                genesis_accounts: Self::genesis_accounts(&self.genesis_key),
                block_time: Duration::from_millis(25),
                scilla_server_socket_directory: self.scilla_server_socket_directory.clone(),
                rewards_per_hour: 204_000_000_000_000_000_000_000u128.into(),
                blocks_per_hour: 3600 * 40,
                minimum_stake: 32_000_000_000_000_000_000u128.into(),
                eth_block_gas_limit: EvmGas(84000000),
                gas_price: 4_761_904_800_000u128.into(),
                main_shard_id: None,
                scilla_address: self.scilla_address.clone(),
                blocks_per_epoch: self.blocks_per_epoch,
                epochs_per_checkpoint: 1,
                scilla_stdlib_dir: self.scilla_stdlib_dir.clone(),
                scilla_ext_libs_path: scilla_ext_libs_path_default(),
                total_native_token_supply: total_native_token_supply_default(),
                contract_upgrades,
                forks: vec![],
                genesis_fork: Fork {
                    scilla_call_gas_exempt_addrs: vec![
                        // Allow the *third* contract deployed by the genesis key to call `scilla_call` for free.
                        secret_key_to_address(&self.genesis_key).create(2),
                    ],
                    ..genesis_fork_default()
                },
                new_view_broadcast_interval: new_view_broadcast_interval_default(),
            },
            block_request_limit: block_request_limit_default(),
            sync: SyncConfig {
                max_blocks_in_flight: max_blocks_in_flight_default(),
                block_request_batch_size: block_request_batch_size_default(),
                prune_interval: options.prune_interval.unwrap_or(u64_max()),
                base_height: options.base_height.unwrap_or(u64_max()),
                ignore_passive: false,
            },
            db: DbConfig::default(),
            failed_request_sleep_duration: failed_request_sleep_duration_default(),
            enable_ots_indices: true,
            max_missed_view_age: max_missed_view_age_default(),
            api_limits: ApiLimits::default(),
        };

        let secret_key = options.secret_key_or_random(self.rng.clone());
        let onchain_key = options.onchain_key_or_random(self.rng.clone());
        let (node, receiver, local_receiver, request_responses) =
            node(config, secret_key, onchain_key, self.nodes.len(), None).unwrap();

        let mut peers = self.nodes.iter().map(|n| n.peer_id).collect_vec();
        peers.shuffle(self.rng.lock().unwrap().deref_mut());
        node.peers.add_peers(peers.clone());

        trace!("Node {}: {}", node.index, node.peer_id);

        let index = node.index;

        self.nodes.push(node);
        self.receivers.push(receiver);
        self.receivers.push(local_receiver);
        self.receivers.push(request_responses);

        index
    }

    // Creates a new network, re-using the private keys, and cloning the data directories.
    pub fn restart(&mut self) {
        let opts = NewNodeOptions {
            secret_key: Some(self.nodes[0].secret_key),
            onchain_key: Some(self.nodes[0].onchain_key.clone()),
            checkpoint: self.nodes[0].inner.config.load_checkpoint.clone(),
            prune_interval: Some(self.nodes[0].inner.config.sync.prune_interval),
            base_height: Some(self.nodes[0].inner.config.sync.base_height),
            state_sync: Some(self.nodes[0].inner.config.db.state_sync),
        };

        self.restart_node_with_options(0, opts, false);
    }

    // Similar to `restart()` but allows for custom options for ONE node.
    pub fn restart_node_with_options(
        &mut self,
        index: usize,
        opts: NewNodeOptions,
        skip_timeouts: bool,
    ) {
        // Collect the keys from the validators
        let keys = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                if i != index {
                    (n.secret_key, n.onchain_key.clone())
                } else {
                    (
                        opts.secret_key.unwrap_or(n.secret_key),
                        opts.onchain_key.clone().unwrap_or(n.onchain_key.clone()),
                    )
                }
            })
            .collect::<Vec<_>>();

        let (nodes, external_receivers, local_receivers, request_response_receivers): (
            Vec<_>,
            Vec<_>,
            Vec<_>,
            Vec<_>,
        ) = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                // Move the persistence over
                let chain_id = self.nodes[i].inner.chain_id;
                let old_data_dir = self.nodes[i]
                    .dir
                    .as_ref()
                    .unwrap()
                    .path()
                    .join(chain_id.eth.to_string());
                let new_data_dir = tempfile::tempdir().unwrap();

                info!(
                    "Moving {} => {}",
                    old_data_dir.display(),
                    new_data_dir.path().display(),
                );

                fs_extra::dir::move_dir(
                    old_data_dir,
                    new_data_dir.path(),
                    &CopyOptions::default().copy_inside(true),
                )
                .unwrap();

                // replace any config
                let config = if index != i {
                    self.nodes[i].inner.config.clone()
                } else {
                    let mut c = self.nodes[i].inner.config.clone();
                    c.load_checkpoint = opts.checkpoint.clone();
                    c.db.state_sync = opts.state_sync.unwrap_or_default();
                    c.sync.prune_interval = opts.prune_interval.unwrap_or(u64::MAX);
                    c.sync.base_height = opts.base_height.unwrap_or(u64::MAX);
                    c
                };

                node(config, key.0, key.1, i, Some(new_data_dir)).unwrap()
            })
            .multiunzip();

        let mut receivers: Vec<_> = external_receivers
            .into_iter()
            .chain(local_receivers)
            .chain(request_response_receivers)
            .collect();

        let mut peers = nodes.iter().map(|n| n.peer_id).collect_vec();
        peers.shuffle(self.rng.lock().unwrap().deref_mut());

        for node in &nodes {
            trace!(
                "Node {}: {} (dir: {})",
                node.index,
                node.peer_id,
                node.dir.as_ref().unwrap().path().to_string_lossy(),
            );
            node.peers.add_peers(peers.clone());
        }

        let (resend_message, receive_resend_message) = mpsc::unbounded_channel::<StreamMessage>();
        let receive_resend_message = UnboundedReceiverStream::new(receive_resend_message).boxed();
        receivers.push(receive_resend_message);

        self.nodes = nodes;
        self.receivers = receivers;
        self.resend_message = resend_message;

        if !skip_timeouts {
            // Now trigger a timeout in all of the nodes until we see network activity again
            // this could of course spin forever, but the test itself should time out.
            loop {
                for node in &self.nodes {
                    node.inner.process_transactions_to_broadcast().unwrap();
                    // Trigger a tick so that block fetching can operate.
                    if node.inner.handle_timeout().unwrap() {
                        return;
                    }
                    zilliqa::time::advance(Duration::from_millis(500));
                }
            }
        }
    }

    fn collect_messages(&mut self) -> Vec<StreamMessage> {
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
                zilliqa::time::advance(Duration::from_millis(1));
                continue;
            }

            // filter out all the propose messages, except node 0. If the proposal is a broadcast,
            // repackage it as direct messages to all nodes except node 0.
            let mut removed_items = Vec::new();

            // Remove the matching messages
            messages.retain(|(s, d, m)| {
                if let AnyMessage::External(ExternalMessage::Proposal(prop)) = m
                    && !prop.transactions.is_empty()
                {
                    removed_items.push((*s, *d, m.clone()));
                    return false;
                }
                true
            });

            // Handle the removed proposes correctly for both cases of broadcast and single cast
            for (s, d, m) in removed_items {
                // If specifically to a node, only allow node 0
                if let Some((dest, id)) = d {
                    // We actually want to allow this message, put it back into the queue
                    if dest == self.nodes[0].peer_id {
                        messages.push((s, Some((dest, id)), m));
                        continue;
                    }

                    // This counts as it getting dropped
                    proposals_seen += 1;
                } else {
                    // Broadcast seen! Push it back into the queue with specific destination of node 0
                    messages.push((s, Some((self.nodes[0].peer_id, RequestId::default())), m));

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
                    node.inner.process_transactions_to_broadcast().unwrap();
                    node.inner.handle_timeout().unwrap();
                });
            }
            return;
        }

        // Immediately handle most InternalMessages:
        //  - any IntershardCall messages to children - forward them (through handle_message) and the child network will handle them
        //  - any LaunchLink messages: just launch the link
        //  - any ExportBlockCheckpoint messages: just run the export
        //  - any LaunchShard messages to the parent - just forward them (through send_to_parent) and the parent network will handle them
        //
        //  Being internal, these messages don't really depend on network conditions or other
        //  nodes, and randomising them would needlessly complicate related tests without being
        //  useful.
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
            AnyMessage::Internal(_, _, InternalMessage::ExportBlockCheckpoint(..)) => {
                self.handle_message(m.clone());
                false
            }
            AnyMessage::Internal(_, _, InternalMessage::LaunchShard(new_network_id)) => {
                // if-let guards are experimental so we nest the check...
                if let Some(send_to_parent) = self.send_to_parent.as_ref() {
                    trace!("Child network {} got LaunchShard({new_network_id}) message; forwarding to parent to handle", self.shard_id);
                    send_to_parent.send(m.clone()).unwrap();
                    false
                } else {
                    true
                }
            }
            AnyMessage::External(ExternalMessage::InjectedProposal(_)) => {
                self.handle_message(m.clone());
                false
            }
            _ => true,
        });

        // Pick a random message
        if !messages.is_empty() {
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
    }

    fn handle_message(&mut self, message: StreamMessage) {
        let (source, destination, ref contents) = message;
        // info!(%source, ?destination);
        let sender_node = self
            .nodes
            .iter()
            .find(|&node| node.peer_id == source)
            .expect("Sender should be on the nodes list");
        let sender_chain_id = sender_node.inner.config.eth_chain_id;
        match contents {
            AnyMessage::Internal(source_shard, destination_shard, internal_message) => {
                trace!(
                    "Handling internal message from node in shard {source_shard}, targetting {destination_shard}"
                );
                match internal_message {
                    InternalMessage::LaunchShard(new_network_id) => {
                        let secret_key = self.find_node(source).unwrap().1.secret_key;
                        if let Some(child_network) = self.children.get_mut(new_network_id) {
                            if child_network.find_node(source).is_none() {
                                trace!(
                                    "Launching shard node for {new_network_id} - adding new node to shard"
                                );
                                child_network.add_node_with_options(NewNodeOptions {
                                    secret_key: Some(secret_key),
                                    ..Default::default()
                                });
                            } else {
                                trace!(
                                    "Received messaged to launch new node in {new_network_id}, but node {source} already exists in that network"
                                );
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
                                    self.scilla_stdlib_dir.clone(),
                                    self.do_checkpoints,
                                    self.blocks_per_epoch,
                                    self.deposit_v3_upgrade_block_height,
                                    self.scilla_server_socket_directory.clone(),
                                ),
                            );
                        }
                    }
                    InternalMessage::LaunchLink(_) | InternalMessage::IntershardCall(_) => {
                        if *destination_shard == self.shard_id {
                            let (destination, _) = destination.expect("Local messages are intended to always have the node's own peerid as destination within in the test harness");
                            let idx_node = self.find_node(destination);
                            if let Some((idx, node)) = idx_node {
                                trace!(
                                    "Handling intershard message {:?} from shard {}, in node {} of shard {}",
                                    internal_message, source_shard, idx, self.shard_id
                                );
                                node.inner
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
                                self.shard_id, destination_shard
                            );
                            network.resend_message.send(message).unwrap();
                        } else if let Some(send_to_parent) = self.send_to_parent.as_ref() {
                            trace!(
                                "Found intershard message that matches none of our children, forwarding it to our parent so they may hopefully route it..."
                            );
                            send_to_parent.send(message).unwrap();
                        } else {
                            warn!("Dropping intershard message for shard that does not exist");
                            trace!(?message);
                        }
                    }
                    InternalMessage::ExportBlockCheckpoint(
                        block,
                        transactions,
                        parent,
                        trie_storage,
                        view_history,
                        output,
                    ) => {
                        assert!(
                            self.do_checkpoints,
                            "Node requested a checkpoint checkpoint export to {}, despite checkpoints beind disabled in the config",
                            output.to_string_lossy()
                        );
                        trace!("Exporting checkpoint to path {}", output.to_string_lossy());
                        db::checkpoint_block_with_state(
                            block,
                            transactions,
                            parent,
                            trie_storage.clone(),
                            *source_shard,
                            view_history.clone(),
                            output,
                        )
                        .unwrap();
                    }
                    InternalMessage::SubscribeToGossipSubTopic(topic) => {
                        debug!("subscribing to topic {:?}", topic);
                    }
                    InternalMessage::UnsubscribeFromGossipSubTopic(topic) => {
                        debug!("unsubscribing from topic {:?}", topic);
                    }
                }
            }
            AnyMessage::External(external_message) => {
                //info!(%external_message, "external");

                let cbor_size =
                    cbor4ii::serde::to_vec(Vec::with_capacity(1024 * 1024), &external_message)
                        .unwrap()
                        .len();

                match destination {
                    Some((destination, _)) => {
                        assert!(
                            cbor_size < zilliqa::constants::MAX_REQUEST_SIZE, // 1MB request
                            "request overflow {cbor_size} {external_message:?}"
                        );

                        // Direct message
                        let (index, node) = self
                            .nodes
                            .iter()
                            .enumerate()
                            .find(|(_, n)| n.peer_id == destination)
                            .unwrap();
                        if !self.disconnected.contains(&index) {
                            let span =
                                tracing::span!(tracing::Level::INFO, "handle_message", index);
                            span.in_scope(|| {
                                let inner = node.inner.clone();
                                // Send to nodes only in the same shard (having same chain_id)
                                if inner.config.eth_chain_id == sender_chain_id {
                                    let response_channel =
                                        ResponseChannel::Remote(self.response_channel_id);
                                    self.response_channel_id += 1;
                                    self.pending_responses
                                        .insert(response_channel.clone(), source);
                                    // Re-route Sync
                                    match external_message {
                                        ExternalMessage::MetaDataRequest(_)
                                        | ExternalMessage::MultiBlockRequest(_)
                                        | ExternalMessage::BlockRequest(_)
                                        | ExternalMessage::PassiveSyncRequest(_) => inner
                                            .handle_broadcast(
                                                source,
                                                external_message.clone(),
                                                response_channel,
                                            )
                                            .unwrap(),
                                        _ => inner
                                            .handle_request(
                                                source,
                                                "(synthetic_id)",
                                                external_message.clone(),
                                                response_channel,
                                            )
                                            .unwrap(),
                                    }
                                }
                            });
                        }
                    }
                    None => {
                        assert!(
                            cbor_size < zilliqa::constants::MAX_GOSSIP_SIZE, // 2MB gossip
                            "broadcast overflow {cbor_size} {external_message:?}"
                        );

                        // Broadcast
                        for (index, node) in self.nodes.iter().enumerate() {
                            if self.disconnected.contains(&index) {
                                continue;
                            }
                            let span =
                                tracing::span!(tracing::Level::INFO, "handle_message", index);
                            span.in_scope(|| {
                                let inner = node.inner.clone();
                                // Send to nodes only in the same shard (having same chain_id)
                                if inner.config.eth_chain_id == sender_chain_id {
                                    // Re-route Proposals from Broadcast to Requests
                                    match external_message {
                                        ExternalMessage::Proposal(_) => inner
                                            .handle_request(
                                                source,
                                                "(faux-id)",
                                                external_message.clone(),
                                                ResponseChannel::Local,
                                            )
                                            .unwrap(),
                                        ExternalMessage::BatchedTransactions(transactions) => {
                                            let mut verified = Vec::new();
                                            for tx in transactions {
                                                let tx = tx.clone().verify().unwrap();
                                                verified.push(tx);
                                            }
                                            inner.handle_broadcast_transactions(verified).unwrap();
                                        }
                                        _ => inner
                                            .handle_broadcast(
                                                source,
                                                external_message.clone(),
                                                ResponseChannel::Local,
                                            )
                                            .unwrap(),
                                    }
                                }
                            });
                        }
                    }
                }
            }
            AnyMessage::Response { channel, message } => {
                //info!(%message, ?channel, "response");

                let cbor_size = cbor4ii::serde::to_vec(Vec::with_capacity(1024 * 1024), &message)
                    .unwrap()
                    .len();
                assert!(
                    cbor_size < zilliqa::constants::MAX_RESPONSE_SIZE, // 10MB response
                    "response overflow {cbor_size} {message:?}"
                );

                // skip on faux response
                if let Some(destination) = self.pending_responses.remove(channel) {
                    let (index, node) = self
                        .nodes
                        .iter()
                        .enumerate()
                        .find(|(_, n)| n.peer_id == destination)
                        .unwrap();
                    if !self.disconnected.contains(&index) {
                        let span = tracing::span!(tracing::Level::INFO, "handle_message", index);
                        span.in_scope(|| {
                            let inner = node.inner.clone();
                            // Send to nodes only in the same shard (having same chain_id)
                            if inner.config.eth_chain_id == sender_chain_id {
                                inner.handle_response(source, message.clone()).unwrap();
                            }
                        });
                    }
                }
            }
        }
    }

    async fn run_until_synced(&mut self, index: usize) {
        let check = loop {
            let i = self.random_index();
            if i != index && !self.disconnected.contains(&i) {
                break i;
            }
        };
        self.run_until(
            |net| {
                let syncing = net
                    .get_node(index)
                    .consensus
                    .read()
                    .sync
                    .am_syncing()
                    .unwrap();
                let height_i = net.get_node(index).get_finalized_height().unwrap();
                let height_c = net.get_node(check).get_finalized_height().unwrap();
                height_c == height_i && height_i > 0 && !syncing
            },
            2000,
        )
        .await
        .unwrap();
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
        hash: &TxHash,
        timeout: usize,
    ) -> TransactionReceipt {
        self.run_until_async(
            || async {
                wallet
                    .get_transaction_receipt(*hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            timeout,
        )
        .await
        .unwrap();
        wallet
            .get_transaction_receipt(*hash)
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn run_until_block(&mut self, wallet: &Wallet, target_block: u64, timeout: usize) {
        self.run_until_async(
            || async { wallet.get_block_number().await.unwrap() >= target_block },
            timeout,
        )
        .await
        .unwrap();
    }

    pub async fn run_until_block_finalized(
        &mut self,
        target_block: u64,
        mut timeout: usize,
    ) -> Result<()> {
        let initial_timeout = timeout;
        let idx = self.random_index();
        let db = self.get_node(idx).db.clone();
        loop {
            if let Some(view) = db.get_finalized_view()?
                && let Some(block) = db.get_block(BlockFilter::View(view))?
                && block.number() >= target_block
            {
                return Ok(());
            }
            if timeout == 0 {
                return Err(anyhow!(
                    "condition was still false after {initial_timeout} ticks"
                ));
            }
            self.tick().await;
            timeout -= 1;
        }
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

    pub async fn wallet_of_node(&mut self, index: usize) -> Wallet {
        let node = &self.nodes[index];
        let wallet = PrivateKeySigner::random_with(self.rng.lock().unwrap().deref_mut());
        let wallet = EthereumWallet::from(wallet);

        ProviderBuilder::new()
            .wallet(wallet)
            .connect_client(RpcClient::new(
                FauxRpcTransport::new(node.rpc_module.clone()),
                true,
            ))
    }

    /// Returns (index, TestNode)
    fn find_node(&self, peer_id: PeerId) -> Option<(usize, &TestNode)> {
        self.nodes
            .iter()
            .enumerate()
            .find(|(_, n)| n.peer_id == peer_id)
    }

    pub fn get_node(&self, index: usize) -> Arc<Node> {
        self.nodes[index].inner.clone()
    }

    pub fn get_node_raw(&self, index: usize) -> &TestNode {
        &self.nodes[index]
    }

    pub fn remove_node(&mut self, idx: usize) -> TestNode {
        let _ = self.receivers.remove(idx);
        self.nodes.remove(idx)
    }

    pub fn node_at(&mut self, index: usize) -> Arc<Node> {
        self.nodes[index].inner.clone()
    }

    // pub async fn rpc_client(&mut self, index: usize) -> Result<LocalRpcLayer> {
    //     Ok(LocalRpcLayer {
    //         id: Arc::new(AtomicU64::new(0)),
    //         rpc_module: self.nodes[index].rpc_module.clone(),
    //     })
    // }

    pub async fn wallet_from_key_with_pubsub(&mut self, key: SigningKey) -> Wallet {
        let wallet = PrivateKeySigner::from_signing_key(key);
        let wallet = EthereumWallet::from(wallet);
        let node = self
            .nodes
            .choose(self.rng.lock().unwrap().deref_mut())
            .unwrap();
        info!(index = node.index, "node selected for wallet");

        ProviderBuilder::new()
            .wallet(wallet)
            .connect_pubsub_with(FauxRpcTransport::new(node.rpc_module.clone()))
            .await
            .unwrap()
    }

    pub async fn wallet_from_key(&mut self, key: SigningKey) -> Wallet {
        let wallet = PrivateKeySigner::from_signing_key(key);
        let wallet = EthereumWallet::from(wallet);
        let node = self
            .nodes
            .choose(self.rng.lock().unwrap().deref_mut())
            .unwrap();
        trace!(index = node.index, "node selected for wallet");

        ProviderBuilder::new()
            .wallet(wallet)
            .connect_with(&FauxRpcTransport::new(node.rpc_module.clone()))
            .await
            .unwrap()
    }

    /// Default genesis wallet
    /// It runs the network for a little bit, so that the automated fillers are able to retreive sane values
    /// Used for nearly all test cases.
    pub async fn genesis_wallet(&mut self) -> Wallet {
        self.run_until_block_finalized(1, 50).await.unwrap(); // run for a little bit
        self.wallet_from_key(self.genesis_key.clone()).await
    }

    /// Genesis wallet that does not run the network at all
    pub async fn genesis_wallet_null(&mut self) -> Wallet {
        self.wallet_from_key(self.genesis_key.clone()).await
    }

    /// Genesis wallet + pubsub
    /// This wallet automatically subscribes to notifications upon submitting transactions.
    /// Used only for subscription related tests.
    pub async fn genesis_pubsub_wallet(&mut self) -> Wallet {
        self.run_until_block_finalized(1, 50).await.unwrap(); // run for a little bit
        self.wallet_from_key_with_pubsub(self.genesis_key.clone())
            .await
    }

    pub async fn random_wallet(&mut self) -> Wallet {
        self.run_until_block_finalized(1, 100).await.unwrap();
        let key = SigningKey::random(self.rng.lock().unwrap().deref_mut());
        self.wallet_from_key(key).await
    }
}

fn format_message(
    nodes: &[TestNode],
    source: PeerId,
    destination: Option<(PeerId, RequestId)>,
    message: &AnyMessage,
) -> String {
    let message = match message {
        AnyMessage::External(message) => format!("{message}"),
        AnyMessage::Internal(_source_shard, _destination_shard, message) => format!("{message}"),
        AnyMessage::Response { message, .. } => format!("{message}"),
    };

    let source_index = nodes.iter().find(|n| n.peer_id == source).unwrap().index;
    if let Some((destination, _)) = destination {
        let destination_index = nodes
            .iter()
            .find(|n| n.peer_id == destination)
            .unwrap()
            .index;
        format!("{source_index} -> {destination_index}: {message}")
    } else {
        format!("{source_index} -> *: {message}")
    }
}

fn compile_contract(path: &str, contract: &str) -> (Contract, Bytes) {
    // create temporary .sol file to avoid solc compilation error
    let full_path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path);
    let source_path = Path::new(&full_path);
    let target_file = tempfile::Builder::new()
        .suffix(".sol")
        .tempfile()
        .expect("tempfile target");
    let target_pathbuf = target_file.into_temp_path().to_path_buf();
    let target_path = &target_pathbuf.as_path();

    std::fs::copy(source_path, target_path).expect("copy .sol");

    // configure solc compiler
    let solc_input = SolcInput::new(
        SolcLanguage::Solidity,
        Source::read_all_files(vec![target_pathbuf.clone()]).expect("missing target"),
        Default::default(),
    )
    .evm_version(EvmVersion::Shanghai); // ensure compatible with EVM version in exec.rs

    // compile .sol file
    let solc = Solc::find_or_install(&semver::Version::new(0, 8, 28)).expect("solc missing");
    let output = solc.compile_exact(&solc_input).expect("solc compile_exact");

    if output.has_error() {
        panic!("failed to compile contract with error  {:?}", output.errors);
    }

    // extract output
    let contract = output
        .get(target_path, contract)
        .expect("output_contracts error");

    let abi = contract.abi.expect("jsonabi error");
    let bytecode = contract.bytecode().expect("bytecode error");

    // Convert from the `alloy` representation of an ABI to the `ethers` representation, via JSON
    let abi = serde_json::from_slice(
        serde_json::to_vec(abi)
            .expect("serialisation abi")
            .as_slice(),
    )
    .expect("deserialisation abi");
    let bytecode = serde_json::from_slice(
        serde_json::to_vec(bytecode)
            .expect("serialisation bytecode")
            .as_slice(),
    )
    .expect("deserialisation bytecode");

    (abi, bytecode)
}

async fn deploy_contract(
    path: &str,
    contract: &str,
    value: u128,
    wallet: &Wallet,
    network: &mut Network,
) -> (Address, TransactionReceipt) {
    let (abi, bytecode) = compile_contract(path, contract);
    let tx_hash = *wallet
        .send_transaction(
            TransactionRequest::default()
                .with_deploy_code(bytecode)
                .value(U256::from(value)),
        )
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(wallet, &tx_hash, 50).await;
    tracing::debug!("Contract {:?} <= {abi:?}", receipt.contract_address);
    (receipt.contract_address.unwrap(), receipt)
}

async fn fund_wallet(network: &mut Network, from_wallet: &Wallet, to_wallet: &Wallet) {
    let hash = *from_wallet
        .send_transaction(
            TransactionRequest::default()
                .with_to(to_wallet.default_signer_address())
                .with_value(U256::from(100_000_000_000_000_000_000u128)),
        )
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(to_wallet, &hash, 100).await;
}

async fn get_reward_address(wallet: &Wallet, staker: &NodePublicKey) -> Address {
    let tx = TransactionRequest::default()
        .with_to(contract_addr::DEPOSIT_PROXY)
        .with_input(
            contracts::deposit::GET_REWARD_ADDRESS
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap(),
        );
    let return_value = wallet.call(tx).await.unwrap();
    contracts::deposit::GET_REWARD_ADDRESS
        .decode_output(&return_value)
        .unwrap()[0]
        .clone()
        .into_address()
        .unwrap()
        .0
        .into()
}

async fn get_stakers(wallet: &Wallet) -> Vec<NodePublicKey> {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::GET_STAKERS
                .encode_input(&[])
                .unwrap()
                .into(),
        ));
    let stakers = wallet.call(tx).await.unwrap();
    let stakers = contracts::deposit::GET_STAKERS
        .decode_output(&stakers)
        .unwrap()[0]
        .clone()
        .into_array()
        .unwrap();

    stakers
        .into_iter()
        .map(|k| NodePublicKey::from_bytes(&k.into_bytes().unwrap()).unwrap())
        .collect()
}

/// A mock transport that directly calls the RPC module w/o any network stack.
///
#[derive(Debug, Clone)]
pub struct FauxRpcTransport {
    rpc_module: RpcModule<Arc<Node>>,
}

#[derive(Debug)]
pub struct FauxBackend {
    pub rpc_module: RpcModule<Arc<Node>>,
    pub interface: ConnectionInterface,
    pub subscriptions: Arc<Mutex<HashMap<u64, mpsc::Receiver<Box<RawValue>>>>>,
}

impl FauxBackend {
    /// Spawn a new backend task.
    pub fn spawn(mut self) {
        let fut = async move {
            let polling = tokio::time::sleep(Duration::from_millis(500));
            tokio::pin!(polling);
            loop {
                select! {
                inst = self.interface.recv_from_frontend() => {
                    match inst {
                        Some(request) => {
                            let req: Request = serde_json::de::from_str(request.get()).unwrap();

                            // There are some hacks in here for `eth_subscribe` and `eth_unsubscribe`. `RpcModule` does not let us control
                            // the `id_provider` and it produces subscription IDs incompatible with Ethereum clients. Specifically, it
                            // produces integers and `ethers-rs` expects hex-encoded integers. Our hacks convert to this encoding.
                            let mut params: Option<Value> = req.params.map(|p| serde_json::to_value(&p).unwrap());
                            if req.method == "eth_unsubscribe" {
                                params.iter_mut().for_each(|p| {
                                    let id = p.as_array_mut().unwrap().get_mut(0).unwrap();
                                    let str_id = id.as_str().unwrap().strip_prefix("0x").unwrap();
                                    let u64_id = u64::from_str_radix(str_id, 16).unwrap();
                                    *id = u64_id.into();
                                    self.subscriptions.lock().unwrap().remove(&u64_id).expect("sub must exist");
                                });
                            }
                            let payload = Request::owned(
                                req.method.to_string(),
                                params.map(|x| serde_json::value::to_raw_value(&x).unwrap()),
                                req.id,
                            );
                            let request = serde_json::to_string(&payload).unwrap();

                            println!("REQ: {}", request.as_str());
                            let (response, rx) = self
                                .rpc_module
                                .raw_json_request(request.as_str(), 1024)
                                .await
                                .expect("no transport errors");
                            println!("RES: {}", response.get());

                            if req.method == "eth_subscribe" {
                                let res: Response = serde_json::from_str(response.get()).unwrap();
                                if let ResponsePayload::Success(id_raw) = res.payload() {
                                    let json_value: Value = serde_json::from_str(id_raw.get()).unwrap();
                                    let id = json_value.as_u64().unwrap();
                                    self.subscriptions.lock().unwrap().insert(id, rx);
                                }
                            }

                            let response: PubSubItem = serde_json::from_str(response.get()).expect("serdes error");
                            self.interface.send_to_frontend(response).expect("send error");
                        },
                        // dispatcher has gone away, or shutdown was received
                        None => {
                            break
                        },
                    }
                }
                _ = &mut polling => {
                    polling.set(tokio::time::sleep(Duration::from_millis(100)));
                    for (_id, rx) in self.subscriptions.lock().unwrap().iter_mut() {
                        if let Ok(item) = rx.try_recv() {
                            println!("NOT: {}", item.get());
                            let item: PubSubItem = serde_json::de::from_str(item.get()).unwrap();
                            self.interface.send_to_frontend(item).unwrap();
                        }
                    }
                }
                }
            }
        };
        fut.spawn_task();
    }
}

impl PubSubConnect for FauxRpcTransport {
    fn is_local(&self) -> bool {
        true
    }

    async fn connect(&self) -> TransportResult<ConnectionHandle> {
        let (handle, interface) = ConnectionHandle::new();
        let backend = FauxBackend {
            rpc_module: self.rpc_module.clone(),
            interface,
            subscriptions: Arc::new(Mutex::new(HashMap::with_capacity(3))),
        };
        backend.spawn();
        Ok(handle)
    }
}

impl TransportConnect for FauxRpcTransport {
    fn is_local(&self) -> bool {
        true
    }

    async fn get_transport(&self) -> Result<BoxTransport, TransportError> {
        Ok(BoxTransport::new(self.clone()))
    }
}

impl FauxRpcTransport {
    /// Create a new [`FauxRpcTransport`] with the given [`RpcModule`].
    pub fn new(rpc_module: RpcModule<Arc<Node>>) -> Self {
        Self { rpc_module }
    }

    async fn handle(self, req: RequestPacket) -> TransportResult<ResponsePacket> {
        let response = match req {
            RequestPacket::Single(req) => ResponsePacket::Single(self.map_request(req).await?),
            RequestPacket::Batch(_) => unimplemented!("support single calls only"),
        };
        Ok(response)
    }

    async fn map_request(&self, req: SerializedRequest) -> TransportResult<Response> {
        let (response, _rx) = self
            .rpc_module
            .raw_json_request(req.serialized().get(), 1024)
            .await
            .expect("no transport errors");

        let response: Response = serde_json::from_str(response.get()).expect("no encoding errors");
        Ok(response)
    }
}

impl Service<RequestPacket> for FauxRpcTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        Box::pin(self.clone().handle(req))
    }
}
