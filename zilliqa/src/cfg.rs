use std::{collections::HashMap, ops::Deref, str::FromStr, time::Duration};

use alloy::{
    hex,
    primitives::{Address, ChainId},
};
use anyhow::{Result, anyhow};
use libp2p::{Multiaddr, PeerId};
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::json;

pub use crate::fork::{Fork, ForkDelta, ForkName, Forks, StagedSchedule, genesis_fork_default};
use crate::{
    constants::{MIN_PRUNE_INTERVAL, MISSED_VIEW_WINDOW},
    credits::RateQuota,
    crypto::{Hash, NodePublicKey},
    transaction::EvmGas,
};

// Note that z2 constructs instances of this to save as a configuration so it must be both
// serializable and deserializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network: String,
    /// Individual configuration for every node to run.
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
    /// The port to listen for P2P messages on. Optional - If not provided a random port will be used.
    #[serde(default)]
    pub p2p_port: u16,
    /// External address for this node. This is the address at which it can be reached by other nodes. This should
    /// include the P2P port. If this is not provided, we will trust other nodes to tell us our external address.
    /// However, be warned that this is insecure and unreliable in real-world networks and we will remove this
    /// behaviour at some point in the future (#1101).
    #[serde(default)]
    pub external_address: Option<Multiaddr>,
    /// The address of another node to dial when this node starts. To join the network, a node must know about at least
    /// one other existing node in the network.
    #[serde(default)]
    pub bootstrap_address: OneOrMany<(PeerId, Multiaddr)>,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    #[serde(default)]
    pub otlp_collector_endpoint: Option<String>,
    #[serde(default = "slow_rpc_queries_handlers_count_default")]
    pub slow_rpc_queries_handlers_count: usize,
}

pub fn slow_rpc_queries_handlers_count_default() -> usize {
    crate::available_threads().saturating_sub(1).max(4)
}

#[derive(Debug, Clone)]
pub struct OneOrMany<T>(pub Vec<T>);

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<T: Serialize> Serialize for OneOrMany<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.len() == 1 {
            self.0[0].serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<T> {
            One(T),
            Many(Vec<T>),
        }

        match Inner::deserialize(deserializer)? {
            Inner::One(t) => Ok(OneOrMany(vec![t])),
            Inner::Many(t) => Ok(OneOrMany(t)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnabledApi {
    EnableAll(String),
    Enabled {
        namespace: String,
        apis: Vec<String>,
    },
}

impl EnabledApi {
    pub fn enabled(&self, api: &str) -> bool {
        // APIs with no namespace default to the 'zilliqa' namespace.
        let (ns, method) = api.split_once('_').unwrap_or(("zilliqa", api));
        match self {
            EnabledApi::EnableAll(namespace) => namespace == ns,
            EnabledApi::Enabled { namespace, apis } => {
                namespace == ns && apis.iter().any(|m| m == method)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiServer {
    /// The port to listen for JSON-RPC requests on.
    pub port: u16,
    /// RPC APIs to enable.
    pub enabled_apis: Vec<EnabledApi>,
    #[serde(default)]
    pub default_quota: Option<RateQuota>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiLimits {
    #[serde(default)]
    pub max_blocks_to_fetch: Option<u64>,

    #[serde(default)]
    pub max_txns_in_block_to_fetch: Option<u64>,

    #[serde(default)]
    pub disable_get_full_state_for_contracts: Vec<Address>,

    #[serde(default = "state_rpc_limit_default")]
    pub state_rpc_limit: usize,

    #[serde(default = "max_rpc_response_size_default")]
    pub max_rpc_response_size: u32,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            max_blocks_to_fetch: None,
            max_txns_in_block_to_fetch: None,
            disable_get_full_state_for_contracts: Vec::new(),
            state_rpc_limit: state_rpc_limit_default(),
            max_rpc_response_size: max_rpc_response_size_default(),
        }
    }
}

fn state_rpc_limit_default() -> usize {
    i64::MAX as usize
}

fn max_rpc_response_size_default() -> u32 {
    10 * 1024 * 1024
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    /// SQLite per-connection page cache;
    #[serde(default = "sql_cache_size_default")]
    pub conn_cache_size: usize,
    /// SQLite auto-checkpoint threshold; 0 to disable;
    #[serde(default = "sql_auto_checkpoint_default")]
    pub auto_checkpoint: usize,
    /// Whether to enable state-sync/state-migration
    #[serde(default)]
    pub state_sync: bool,
    /// RocksDB block cache size, in bytes.
    #[serde(default = "rocksdb_cache_size_default")]
    pub rocksdb_cache_size: usize,
    /// State cache size
    #[serde(default = "rocksdb_state_cache_size_default")]
    pub rocksdb_state_cache_size: usize,
    /// Block size
    #[serde(default = "rocksdb_block_size_default")]
    pub rocksdb_block_size: usize,
    /// Target File Size
    #[serde(default = "rocksdb_memtable_budget_default")]
    pub rocksdb_memtable_budget: usize,
    /// The N number of historical blocks to be kept in the DB during pruning. N >= 300.
    #[serde(default = "u64_max")]
    pub prune_interval: u64,
}

fn rocksdb_block_size_default() -> usize {
    1 << 14 // 16KB reduces in-memory indexes
}

fn rocksdb_memtable_budget_default() -> usize {
    1 << 31 // 2GB is a reasonable default
}

fn rocksdb_cache_size_default() -> usize {
    1 << 30 // 1GB is enough for normal nodes
}

fn rocksdb_state_cache_size_default() -> usize {
    1 << 31 // 2GB is a reasonable default
}

fn sql_cache_size_default() -> usize {
    256 // 32KB * 256 = 8MB (SQLite default)
}

fn sql_auto_checkpoint_default() -> usize {
    1_000
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            conn_cache_size: sql_cache_size_default(),
            auto_checkpoint: sql_auto_checkpoint_default(),
            state_sync: false,
            prune_interval: u64_max(),
            rocksdb_cache_size: rocksdb_cache_size_default(),
            rocksdb_state_cache_size: rocksdb_state_cache_size_default(),
            rocksdb_block_size: rocksdb_block_size_default(),
            rocksdb_memtable_budget: rocksdb_memtable_budget_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    /// The maximum number of blocks to have outstanding requests for at a time when syncing.
    #[serde(default = "max_blocks_in_flight_default")]
    pub max_blocks_in_flight: usize,
    /// The maximum number of blocks to request in a single message when syncing.
    #[serde(default = "block_request_batch_size_default")]
    pub block_request_batch_size: usize,
    /// Lowest block to sync from, during passive-sync.
    /// Cannot be set if prune_interval is set.
    #[serde(default = "u64_max")]
    pub base_height: u64,
    /// Service passive-sync flag
    #[serde(default)]
    pub ignore_passive: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_blocks_in_flight: max_blocks_in_flight_default(),
            block_request_batch_size: block_request_batch_size_default(),
            base_height: u64_max(),
            ignore_passive: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteChain {
    pub chain_id: ChainId,
    pub bundler_url: String,
    pub watcher_url: String,
    pub entrypoint: Address,
    pub gateway: Address,
    pub sender: Address,
    pub paymaster: Address,
    #[serde(default)]
    pub allow_loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// RPC API endpoints to expose.
    #[serde(default)]
    pub api_servers: Vec<ApiServer>,
    /// Chain identifier. Doubles as shard_id internally.
    #[serde(default = "eth_chain_id_default")]
    pub eth_chain_id: u64,
    /// Consensus-specific data.
    pub consensus: ConsensusConfig,
    /// The maximum duration between a recieved block's timestamp and the current time. Defaults to 10 seconds.
    #[serde(default = "allowed_timestamp_skew_default")]
    pub allowed_timestamp_skew: Duration,
    /// The location of persistence data. If not set, uses a temporary path.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// The directory holding the blocked-recipients files named by forks. Node-local: only the
    /// files' contents are consensus-critical, not where they live. Defaults to `data_dir`; in
    /// the Docker image the files are baked into `/blocked_recipients`, outside the data volume.
    #[serde(default)]
    pub blocked_recipients_dir: Option<String>,
    #[serde(default)]
    pub escrow_raw_lists_dir: Option<String>,
    /// Size of the in-memory state trie cache, in bytes. Defaults to 256 MiB.
    #[serde(default = "state_cache_size_default")]
    pub state_cache_size: usize,
    /// Persistence checkpoint to load.
    #[serde(default)]
    pub load_checkpoint: Option<Checkpoint>,
    /// Whether to enable exporting checkpoint state checkpoint files.
    #[serde(default)]
    pub do_checkpoints: bool,
    /// The maximum number of blocks we will send to another node in a single message.
    #[serde(default = "block_request_limit_default")]
    pub block_request_limit: usize,
    /// When a block request to a peer fails, do not send another request to this peer for this amount of time.
    /// Defaults to 10 seconds.
    #[serde(default = "failed_request_sleep_duration_default")]
    pub failed_request_sleep_duration: Duration,
    /// Enable additional indices used by some Otterscan APIs. Enabling this will use more disk space and block processing will take longer.
    #[serde(default)]
    pub enable_ots_indices: bool,
    /// Sync configuration
    #[serde(default)]
    pub sync: SyncConfig,
    /// Database configuration
    #[serde(default)]
    pub db: DbConfig,
    /// Maximum age of missed view items older than `LAG_BEHIND_CURRENT_VIEW` that are retained in the history.
    /// The default is sufficient to compute the leaders of the next views, but does not allow the node to compute leaders of past views.
    #[serde(default = "max_missed_view_age_default")]
    pub max_missed_view_age: u64,
    #[serde(default)]
    /// Rate list for each RPC method
    pub credit_rates: HashMap<String, u64>,
    #[serde(default)]
    pub api_limits: ApiLimits,
    #[serde(default)]
    pub remote_chains: Vec<RemoteChain>,
    #[serde(default)]
    pub bundler_port: u16,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            api_servers: vec![],
            eth_chain_id: eth_chain_id_default(),
            consensus: ConsensusConfig::default(),
            allowed_timestamp_skew: allowed_timestamp_skew_default(),
            data_dir: None,
            blocked_recipients_dir: None,
            escrow_raw_lists_dir: None,
            state_cache_size: state_cache_size_default(),
            load_checkpoint: None,
            do_checkpoints: false,
            block_request_limit: block_request_limit_default(),
            sync: SyncConfig::default(),
            db: DbConfig::default(),
            failed_request_sleep_duration: failed_request_sleep_duration_default(),
            enable_ots_indices: false,
            max_missed_view_age: max_missed_view_age_default(),
            credit_rates: HashMap::new(),
            api_limits: ApiLimits::default(),
            remote_chains: Default::default(),
            bundler_port: 4200u16,
        }
    }
}

impl NodeConfig {
    pub fn validate(&self) -> Result<()> {
        if let serde_json::Value::Object(map) =
            serde_json::to_value(self.consensus.contract_upgrades.clone())?
        {
            for (contract, block_height) in map {
                if block_height.as_u64().unwrap_or(0) % self.consensus.blocks_per_epoch != 0 {
                    return Err(anyhow!(
                        "Contract upgrades must be configured to occur at epoch boundaries. blocks_per_epoch: {}, contract {} configured to be upgraded block: {}",
                        self.consensus.blocks_per_epoch,
                        contract,
                        block_height
                    ));
                }
            }
        }

        // deprecated settings
        anyhow::ensure!(
            self.state_cache_size == state_cache_size_default(),
            "state_cache_size is deprecated. Use db.rocksdb_cache_size and db.rocksdb_state_cache_size instead."
        );
        // sync/prune settings
        anyhow::ensure!(
            self.sync.base_height == u64_max() || self.db.prune_interval == u64_max(),
            "sync.base_height and sync.prune_interval cannot be set at the same time"
        );
        anyhow::ensure!(
            self.db.prune_interval >= MIN_PRUNE_INTERVAL,
            "sync.prune_interval must be at least {MIN_PRUNE_INTERVAL}",
        );
        anyhow::ensure!(
            self.db.prune_interval == u64::MAX || !self.do_checkpoints,
            "state_prune and do_checkpoints cannot be set at the same time"
        );
        anyhow::ensure!(
            self.sync.block_request_batch_size >= 10,
            "block_request_batch_size must be at least 10"
        );
        anyhow::ensure!(
            self.sync.max_blocks_in_flight <= 1000,
            "max_blocks_in_flight must be at most 1000"
        );
        anyhow::ensure!(
            self.max_missed_view_age >= MISSED_VIEW_WINDOW,
            "max_missed_view_age must be at least {MISSED_VIEW_WINDOW}"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Location of the checkpoint
    pub file: String,
    /// Trusted hash of the checkpoint block
    #[serde(
        serialize_with = "serialize_hash_hex",
        deserialize_with = "deserialize_hash_hex"
    )]
    pub hash: Hash,
}

fn serialize_hash_hex<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(hash.0).serialize(serializer)
}

fn deserialize_hash_hex<'de, D>(deserializer: D) -> Result<Hash, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = <String>::deserialize(deserializer)?;
    let bytes = hex::decode(s).unwrap();
    Hash::try_from(bytes.as_slice()).map_err(|_| {
        de::Error::invalid_value(de::Unexpected::Bytes(&bytes), &"a 32-byte hex value")
    })
}

pub fn u64_max() -> u64 {
    u64::MAX
}

pub fn allowed_timestamp_skew_default() -> Duration {
    Duration::from_secs(60)
}

pub fn state_cache_size_default() -> usize {
    usize::MIN // no longer used
}

pub fn eth_chain_id_default() -> u64 {
    700 + 0x8000
}

pub fn block_request_limit_default() -> usize {
    100
}

pub fn max_blocks_in_flight_default() -> usize {
    1000
}

pub fn block_request_batch_size_default() -> usize {
    100
}

pub fn failed_request_sleep_duration_default() -> Duration {
    Duration::from_secs(10)
}

pub fn max_missed_view_age_default() -> u64 {
    MISSED_VIEW_WINDOW * (blocks_per_epoch_default() + 1)
}

/// Wrapper for [u128] that (de)serializes with a string. `serde_toml` does not support `u128`s.
#[derive(Copy, Clone, Debug)]
pub struct Amount(pub u128);

impl From<u128> for Amount {
    fn from(value: u128) -> Self {
        Amount(value)
    }
}

impl Deref for Amount {
    type Target = u128;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Amount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut res = String::deserialize(deserializer)?;
        // Remove underscores
        res.retain(|c| c != '_');
        Ok(Amount(
            u128::from_str(&res).map_err(serde::de::Error::custom)?,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScillaExtLibsPathInZq2(pub String);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScillaExtLibsPathInScilla(pub String);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScillaExtLibsPath {
    /// Where are the external libraries stored in zq2 servers' filesystem
    pub zq2: ScillaExtLibsPathInZq2,
    /// Where are the external libraries stored in scilla servers' filesystem
    pub scilla: ScillaExtLibsPathInScilla,
}

impl ScillaExtLibsPath {
    pub fn generate_random_subdirs(&self) -> (ScillaExtLibsPathInZq2, ScillaExtLibsPathInScilla) {
        let sub_directory: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        (
            ScillaExtLibsPathInZq2(format!("{}/{}", self.zq2.0, sub_directory)),
            ScillaExtLibsPathInScilla(format!("{}/{}", self.scilla.0, sub_directory)),
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConsensusConfig {
    /// If main, deploy a shard registry contract.
    #[serde(default = "default_true")]
    pub is_main: bool,
    /// If not main, parent main shard.
    #[serde(default)]
    pub main_shard_id: Option<u64>,
    /// The maximum time to wait for consensus to proceed as normal, before proposing a new view.
    #[serde(default = "consensus_timeout_default")]
    pub consensus_timeout: Duration,
    /// The initially staked deposits in the deposit contract at genesis, composed of
    /// (public key, peerId, amount, reward address) tuples.
    #[serde(default)]
    pub genesis_deposits: Vec<GenesisDeposit>,
    /// Accounts that will be pre-funded at genesis.
    #[serde(default)]
    pub genesis_accounts: Vec<(Address, Amount)>,
    /// The expected time between blocks when no views are missed.
    #[serde(default = "block_time_default")]
    pub block_time: Duration,
    /// Address of the Scilla server. Defaults to "http://localhost:62831".
    #[serde(default = "scilla_address_default")]
    pub scilla_address: String,
    /// Where (in the Scilla server's filesystem) is the library directory containing Scilla library functions?
    #[serde(default = "scilla_stdlib_dir_default")]
    pub scilla_stdlib_dir: String,
    /// Where are the external libraries are stored on zq2 and scilla server's filesystem so that scilla server can find them?
    #[serde(default = "scilla_ext_libs_path_default")]
    pub scilla_ext_libs_path: ScillaExtLibsPath,
    /// Directory in which the Unix domain socket used by the Scilla state server is created. If the Scilla process is
    /// running in Docker, this directory should be mounted inside the container too. Defaults to
    /// "/tmp/scilla-state-server".
    #[serde(default = "scilla_server_socket_directory_default")]
    pub scilla_server_socket_directory: String,
    /// Reward amount issued per hour, in Wei.
    pub rewards_per_hour: Amount,
    /// Number of blocks per hour. The reward per block is set at (rewards_per_hour/blocks_per_hour) Wei.
    pub blocks_per_hour: u64,
    /// The minimum stake passed into the deposit contract constructor at genesis, in Wei. Subsequent changes to this
    /// parameter will have no effect. You must not use this parameter at run-time; obtain the minimum stake in effect
    /// from the contract - otherwise if this value ever changes, there will be a mismatch between what the deposit
    /// contract believes and what the validators believe to be the minimum stake.
    pub minimum_stake: Amount,
    /// Maximum amount of gas permitted in a single block; any transactions over this
    /// will be held until the next block. The white paper specifies this as 84_000_000.
    pub eth_block_gas_limit: EvmGas,
    #[serde(default = "blocks_per_epoch_default")]
    pub blocks_per_epoch: u64,
    #[serde(default = "epochs_per_checkpoint_default")]
    pub epochs_per_checkpoint: u64,
    /// The gas price, in Wei per unit of EVM gas.
    pub gas_price: Amount,
    /// The total supply of native token in the network in Wei. Any funds which are not immediately assigned to an account (via genesis_accounts and genesis_deposits env vars) will be assigned to the zero account (0x0).
    #[serde(default = "total_native_token_supply_default")]
    pub total_native_token_supply: Amount,
    /// The block heights at which we perform EIP-1967 contract upgrades
    /// Contract upgrades occur only at epoch boundaries, ie at block heights which are a multiple of blocks_per_epoch
    #[serde(default)]
    pub contract_upgrades: ContractUpgrades,
    /// The initial fork configuration at genesis block. This provides a complete description of the execution behavior
    /// at the genesis block.
    #[serde(default = "genesis_fork_default")]
    pub genesis_fork: Fork,
    /// Forks in block execution logic. Each entry describes the difference in logic and the block height at which that
    /// difference applies.
    #[serde(default)]
    pub forks: Vec<ForkDelta>,
    /// Interval at which NewView messages are broadcast when node is in timeout
    /// Defaut of 0 means never broadcast
    #[serde(default = "new_view_broadcast_interval_default")]
    pub new_view_broadcast_interval: Duration,
}

impl ConsensusConfig {
    /// Generates a list of forks by applying the delta forks initially to the genesis fork and then to the previous one.
    /// The genesis fork is the initial fork configuration at the genesis block.
    pub fn get_forks(&self) -> Result<Forks> {
        if self.genesis_fork.at_height != 0 {
            return Err(anyhow!("first fork must start at height 0"));
        }

        let mut delta_forks = self.forks.clone();
        delta_forks.sort_unstable_by_key(|f| f.at_height);

        let forks =
            delta_forks
                .into_iter()
                .fold(vec![self.genesis_fork.clone()], |mut forks, delta| {
                    let last_fork = forks.last().unwrap(); // Safe to call unwrap because we always have genesis_fork
                    let new_fork = last_fork.apply_delta_fork(&delta);
                    forks.push(new_fork);
                    forks
                });

        Ok(Forks(forks))
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            is_main: default_true(),
            main_shard_id: None,
            consensus_timeout: consensus_timeout_default(),
            genesis_deposits: vec![],
            genesis_accounts: vec![],
            block_time: block_time_default(),
            scilla_address: scilla_address_default(),
            scilla_stdlib_dir: scilla_stdlib_dir_default(),
            scilla_ext_libs_path: scilla_ext_libs_path_default(),
            scilla_server_socket_directory: scilla_server_socket_directory_default(),
            rewards_per_hour: 204_000_000_000_000_000_000_000u128.into(),
            blocks_per_hour: 3600 * 40,
            minimum_stake: 32_000_000_000_000_000_000u128.into(),
            eth_block_gas_limit: EvmGas(84000000),
            blocks_per_epoch: blocks_per_epoch_default(),
            epochs_per_checkpoint: epochs_per_checkpoint_default(),
            gas_price: 4_761_904_800_000u128.into(),
            total_native_token_supply: total_native_token_supply_default(),
            contract_upgrades: ContractUpgrades::default(),
            forks: vec![],
            genesis_fork: genesis_fork_default(),
            new_view_broadcast_interval: new_view_broadcast_interval_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisDeposit {
    pub public_key: NodePublicKey,
    pub peer_id: PeerId,
    pub stake: Amount,
    pub reward_address: Address,
    pub control_address: Address,
}

pub fn consensus_timeout_default() -> Duration {
    Duration::from_secs(15)
}

pub fn block_time_default() -> Duration {
    Duration::from_millis(1000)
}

pub fn scilla_address_default() -> String {
    String::from("http://localhost:62831")
}

// This path is as viewed from Scilla, not zq2.
pub fn scilla_stdlib_dir_default() -> String {
    String::from("/scilla/0/_build/default/src/stdlib/")
}

pub fn scilla_ext_libs_path_default() -> ScillaExtLibsPath {
    ScillaExtLibsPath {
        zq2: ScillaExtLibsPathInZq2(String::from("/tmp/scilla_ext_libs")),
        scilla: ScillaExtLibsPathInScilla(String::from("/scilla_ext_libs")),
    }
}

pub fn scilla_server_socket_directory_default() -> String {
    String::from("/tmp/scilla-state-server")
}

pub fn blocks_per_epoch_default() -> u64 {
    3600
}

pub fn epochs_per_checkpoint_default() -> u64 {
    24
}

fn default_true() -> bool {
    true
}

pub fn total_native_token_supply_default() -> Amount {
    Amount::from(21_000_000_000_000_000_000_000_000_000)
}

pub fn withdrawal_period_default() -> u64 {
    // 2 weeks worth of blocks with 1 second block time
    2 * 7 * 24 * 60 * 60
}

pub fn new_view_broadcast_interval_default() -> Duration {
    Duration::from_secs(300)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinitialiseParams {
    /// The minimum number of blocks a staker must wait before being able to withdraw unstaked funds
    pub withdrawal_period: u64,
}

impl Default for ReinitialiseParams {
    fn default() -> Self {
        Self {
            withdrawal_period: withdrawal_period_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractUpgradeConfig {
    pub height: u64,
    pub reinitialise_params: Option<ReinitialiseParams>,
}

impl ContractUpgradeConfig {
    pub fn from_height(height: u64) -> Self {
        Self {
            height,
            reinitialise_params: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractUpgrades {
    pub deposit_v3: Option<ContractUpgradeConfig>,
    pub deposit_v4: Option<ContractUpgradeConfig>,
    pub deposit_v5: Option<ContractUpgradeConfig>,
    pub deposit_v6: Option<ContractUpgradeConfig>,
    pub deposit_v7: Option<ContractUpgradeConfig>,
    pub deposit_v8: Option<ContractUpgradeConfig>,
    pub deposit_v9: Option<ContractUpgradeConfig>,
}

impl ContractUpgrades {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deposit_v3: Option<ContractUpgradeConfig>,
        deposit_v4: Option<ContractUpgradeConfig>,
        deposit_v5: Option<ContractUpgradeConfig>,
        deposit_v6: Option<ContractUpgradeConfig>,
        deposit_v7: Option<ContractUpgradeConfig>,
        deposit_v8: Option<ContractUpgradeConfig>,
        deposit_v9: Option<ContractUpgradeConfig>,
    ) -> ContractUpgrades {
        Self {
            deposit_v3,
            deposit_v4,
            deposit_v5,
            deposit_v6,
            deposit_v7,
            deposit_v8,
            deposit_v9,
        }
    }
    pub fn to_toml(&self) -> toml::Value {
        // toml doesn't like Option types. We need to manually map items in struct removing keys for None values as we go
        // ContractUpgrades's values are only either u64, None or a json object
        fn serde_value_to_toml_value(input: serde_json::Value) -> toml::Value {
            toml::Value::Table(
                input
                    .as_object()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .filter_map(|(k, v)| {
                        if v.is_null() {
                            // Ignore None values
                            None
                        } else if v.is_u64() {
                            // Parse ints
                            Some((k, toml::Value::Integer(v.as_u64().unwrap() as i64)))
                        } else {
                            // Recursively parse objects
                            Some((k, serde_value_to_toml_value(v)))
                        }
                    })
                    .collect(),
            )
        }
        serde_value_to_toml_value(json!(self))
    }
}

impl Default for ContractUpgrades {
    fn default() -> Self {
        Self {
            deposit_v3: None,
            deposit_v4: None,
            deposit_v5: Some(ContractUpgradeConfig {
                height: 0,
                reinitialise_params: Some(ReinitialiseParams::default()),
            }),
            deposit_v6: Some(ContractUpgradeConfig {
                height: 0,
                reinitialise_params: None,
            }),
            deposit_v7: Some(ContractUpgradeConfig {
                height: 0,
                reinitialise_params: Some(ReinitialiseParams::default()),
            }),
            deposit_v8: Some(ContractUpgradeConfig {
                height: 0,
                reinitialise_params: Some(ReinitialiseParams::default()),
            }),
            deposit_v9: Some(ContractUpgradeConfig {
                height: 0,
                // v9 is a logic-only security patch; preserve the existing unbonding period
                // (no-arg reinitialize) rather than resetting it as v7/v8 do.
                reinitialise_params: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule_fork(at_height: u64, start: u64, file: &str) -> Fork {
        Fork {
            at_height,
            blocked_recipients_start_height: start,
            blocked_recipients_file: file.to_owned(),
            ..Default::default()
        }
    }

    /// Startup opens every file any fork names - schedules millions of blocks away included -
    /// while the per-block gate stays closed until `forks.get(height)` carries the pair.
    #[test]
    fn schedules_are_collected_across_all_forks() {
        let forks = Forks(vec![
            schedule_fork(0, 0, ""),
            schedule_fork(5_000_000, 5_000_100, "one.bin"),
            // Same pair carried forward: still the same schedule.
            schedule_fork(5_500_000, 5_000_100, "one.bin"),
            // A new pair replaces it; "one.bin" is never consulted from here on.
            schedule_fork(6_000_000, 6_000_000, "two.bin"),
        ]);

        assert_eq!(
            forks.blocked_recipient_schedules().unwrap(),
            vec![
                StagedSchedule {
                    file: "one.bin".into(),
                    start_height: 5_000_100,
                    replaced_at: Some(6_000_000),
                },
                StagedSchedule {
                    file: "two.bin".into(),
                    start_height: 6_000_000,
                    replaced_at: None,
                },
            ]
        );
        // Executing a block below the activation still sees no schedule.
        assert_eq!(forks.get(100).blocked_recipients_start_height, 0);
        assert_eq!(forks.get(5_000_000).blocked_recipients_file, "one.bin");
    }

    #[test]
    fn v2_schedules_run_alongside_v1_and_share_the_file_namespace() {
        let v2 = |at_height, start, file: &str| Fork {
            at_height,
            blocked_recipients_start_height_v2: start,
            blocked_recipients_file_v2: file.to_owned(),
            ..Default::default()
        };
        let forks = Forks(vec![
            schedule_fork(0, 0, ""),
            schedule_fork(100, 100, "one.bin"),
            Fork {
                blocked_recipients_start_height: 100,
                blocked_recipients_file: "one.bin".to_owned(),
                ..v2(200, 200, "two.bin")
            },
            Fork {
                blocked_recipients_start_height: 300,
                blocked_recipients_file: "three.bin".to_owned(),
                ..v2(300, 200, "two.bin")
            },
        ]);
        assert_eq!(
            forks.blocked_recipient_schedules().unwrap(),
            vec![
                StagedSchedule {
                    file: "one.bin".into(),
                    start_height: 100,
                    replaced_at: Some(300),
                },
                StagedSchedule {
                    file: "three.bin".into(),
                    start_height: 300,
                    replaced_at: None,
                },
                StagedSchedule {
                    file: "two.bin".into(),
                    start_height: 200,
                    replaced_at: None,
                },
            ]
        );
        assert_eq!(forks.get(250).blocked_recipients_file, "one.bin");
        assert_eq!(forks.get(250).blocked_recipients_file_v2, "two.bin");

        let forks = Forks(vec![schedule_fork(0, 0, ""), v2(10, 0, "two.bin")]);
        let error = forks.blocked_recipient_schedules().unwrap_err().to_string();
        assert!(error.contains("blocked_recipients_file_v2"), "{error}");

        let forks = Forks(vec![
            schedule_fork(0, 0, ""),
            schedule_fork(10, 10, "one.bin"),
            v2(20, 20, "one.bin"),
        ]);
        let error = forks.blocked_recipient_schedules().unwrap_err().to_string();
        assert!(error.contains("two schedules"), "{error}");
    }

    #[test]
    fn v3_schedules_run_alongside_v1_and_v2_and_share_the_file_namespace() {
        let v3 = |at_height, start, file: &str| Fork {
            at_height,
            blocked_recipients_start_height_v3: start,
            blocked_recipients_file_v3: file.to_owned(),
            ..Default::default()
        };
        let forks = Forks(vec![
            schedule_fork(0, 0, ""),
            schedule_fork(100, 100, "one.bin"),
            Fork {
                blocked_recipients_start_height: 100,
                blocked_recipients_file: "one.bin".to_owned(),
                blocked_recipients_start_height_v2: 200,
                blocked_recipients_file_v2: "two.bin".to_owned(),
                ..v3(200, 250, "three.bin")
            },
        ]);
        assert_eq!(
            forks.blocked_recipient_schedules().unwrap(),
            vec![
                StagedSchedule {
                    file: "one.bin".into(),
                    start_height: 100,
                    replaced_at: None,
                },
                StagedSchedule {
                    file: "two.bin".into(),
                    start_height: 200,
                    replaced_at: None,
                },
                StagedSchedule {
                    file: "three.bin".into(),
                    start_height: 250,
                    replaced_at: None,
                },
            ]
        );
        assert_eq!(forks.get(250).blocked_recipients_file_v3, "three.bin");

        let forks = Forks(vec![schedule_fork(0, 0, ""), v3(10, 0, "three.bin")]);
        let error = forks.blocked_recipient_schedules().unwrap_err().to_string();
        assert!(error.contains("blocked_recipients_file_v3"), "{error}");

        let forks = Forks(vec![
            schedule_fork(0, 0, ""),
            schedule_fork(10, 10, "one.bin"),
            v3(20, 20, "one.bin"),
        ]);
        let error = forks.blocked_recipient_schedules().unwrap_err().to_string();
        assert!(error.contains("two schedules"), "{error}");
    }

    #[test]
    fn no_schedules_without_configuration() {
        let forks = Forks(vec![schedule_fork(0, 0, "")]);
        assert_eq!(forks.blocked_recipient_schedules().unwrap(), vec![]);
    }

    #[test]
    fn schedule_validation_rejects_silent_sweep_skips() {
        // File and height must come together.
        for (start, file) in [(0, "one.bin"), (10, "")] {
            let forks = Forks(vec![schedule_fork(0, 0, ""), schedule_fork(5, start, file)]);
            assert!(
                forks.blocked_recipient_schedules().is_err(),
                "{start} {file:?}"
            );
        }

        // A start below the introducing fork would skip that many batches of addresses.
        let forks = Forks(vec![
            schedule_fork(0, 0, ""),
            schedule_fork(100, 50, "one.bin"),
        ]);
        let error = forks.blocked_recipient_schedules().unwrap_err().to_string();
        assert!(error.contains("before its own activation"), "{error}");

        // A file cannot serve two schedules: its batch index only fits one start height.
        let forks = Forks(vec![
            schedule_fork(0, 0, ""),
            schedule_fork(10, 10, "one.bin"),
            schedule_fork(20, 20, "two.bin"),
            schedule_fork(30, 30, "one.bin"),
        ]);
        let error = forks.blocked_recipient_schedules().unwrap_err().to_string();
        assert!(error.contains("two schedules"), "{error}");
    }

    #[test]
    fn test_get_forks_with_no_forks() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 1);
        assert_eq!(forks.get(0).at_height, 0);
    }

    #[test]
    fn test_get_forks_with_one_fork() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![ForkDelta {
                at_height: 10,
                executable_blocks: None,
                failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                call_mode_1_sets_caller_to_parent_caller: Some(false),
                scilla_messages_can_call_evm_contracts: None,
                scilla_contract_creation_increments_account_balance: Some(false),
                scilla_json_preserve_order: None,
                scilla_call_respects_evm_state_changes: None,
                only_mutated_accounts_update_state: None,
                scilla_call_gas_exempt_addrs: vec![],
                scilla_block_number_returns_current_block: None,
                scilla_maps_are_encoded_correctly: None,
                transfer_gas_fee_to_zero_account: None,
                apply_scilla_delta_when_evm_succeeded: None,
                apply_state_changes_only_if_transaction_succeeds: None,
                scilla_deduct_funds_from_actual_sender: None,
                fund_accounts_from_zero_account: None,
                scilla_delta_maps_are_applied_correctly: None,
                scilla_server_unlimited_response_size: None,
                scilla_failed_txn_correct_balance_deduction: None,
                scilla_transition_proper_order: None,
                evm_to_scilla_value_transfer_zero: None,
                restore_xsgd_contract: None,
                evm_exec_failure_causes_scilla_precompile_to_fail: None,
                revert_restore_xsgd_contract: None,
                scilla_fix_contract_code_removal_on_evm_tx: None,
                restore_ignite_wallet_contracts: None,
                prevent_zil_transfer_from_evm_to_scilla_contract: None,
                scilla_failed_txn_correct_gas_fee_charged: None,
                check_minimum_gas_price: None,
                inject_access_list: None,
                use_max_gas_priority_fee: None,
                failed_zil_transfers_to_eoa_proper_fee_deduction: None,
                validator_jailing: None,
                scilla_empty_maps_are_encoded_correctly: None,
                cancun_active: None,
                scilla_call_gas_exempt_addrs_v2: vec![],
                randao_support: None,
                evm_to_scilla_strings_encoded_properly: None,
                dont_overwrite_evm_accounts_from_stale_scilla_state: None,
                make_transfers_in_scilla_precompiles_with_journal_api: None,
                disable_interop_native_zil_transfers_0: None,
                tighten_precompile_rules: None,
                allow_scilla_call_precompile_to_be_called_from_addresses: None,
                distribute_rewards_every_epoch: None,
                pectra_active: None,
                disable_zilliqa_txn_execution: None,
                blocked_recipients_start_height: None,
                blocked_recipients_file: None,
                blocked_recipients_start_height_v2: None,
                blocked_recipients_file_v2: None,
                blocked_recipients_start_height_v3: None,
                blocked_recipients_file_v3: None,
                blocked_recipients_start_height_v4: None,
                blocked_recipients_file_v4: None,
                zil_transfers_only_to_escrow: None,
                deploy_escrow_contract_v1: None,
                evm_gas_fee_credited_once_to_zero_account: None,
                disable_permanently_scilla_precompiles_v1: vec![],
                deploy_escrow_mintable_contract_v1: None,
                escrow_mintable_admin: None,
                escrow_lodge_start_height: None,
                escrow_lodge_file: None,
                invalidate_zq1_staking_contract: None,
                staked_zils_file: None,
                restore_denylisted_accounts_v1: None,
                remove_scilla_contracts_from_evm_delta: None,
            }],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 2);
        assert_eq!(forks.get(0).at_height, 0);
        assert_eq!(forks.get(11).at_height, 10);
        assert!(!forks.get(10).call_mode_1_sets_caller_to_parent_caller);
        assert!(
            !forks
                .get(10)
                .scilla_contract_creation_increments_account_balance
        );
    }

    #[test]
    fn test_get_forks_with_multiple_forks() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![
                ForkDelta {
                    at_height: 10,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: Some(true),
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: Some(true),
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: Some(true),
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                    restore_ignite_wallet_contracts: None,
                    prevent_zil_transfer_from_evm_to_scilla_contract: None,
                    scilla_failed_txn_correct_gas_fee_charged: None,
                    check_minimum_gas_price: None,
                    inject_access_list: None,
                    use_max_gas_priority_fee: None,
                    failed_zil_transfers_to_eoa_proper_fee_deduction: None,
                    validator_jailing: Some(false),
                    scilla_empty_maps_are_encoded_correctly: Some(false),
                    cancun_active: Some(false),
                    scilla_call_gas_exempt_addrs_v2: vec![],
                    randao_support: Some(false),
                    evm_to_scilla_strings_encoded_properly: None,
                    dont_overwrite_evm_accounts_from_stale_scilla_state: None,
                    make_transfers_in_scilla_precompiles_with_journal_api: None,
                    disable_interop_native_zil_transfers_0: None,
                    tighten_precompile_rules: None,
                    allow_scilla_call_precompile_to_be_called_from_addresses: None,
                    distribute_rewards_every_epoch: None,
                    pectra_active: Some(false),
                    disable_zilliqa_txn_execution: None,
                    blocked_recipients_start_height: None,
                    blocked_recipients_file: None,
                    blocked_recipients_start_height_v2: None,
                    blocked_recipients_file_v2: None,
                    blocked_recipients_start_height_v3: None,
                    blocked_recipients_file_v3: None,
                    blocked_recipients_start_height_v4: None,
                    blocked_recipients_file_v4: None,
                    zil_transfers_only_to_escrow: None,
                    deploy_escrow_contract_v1: None,
                    evm_gas_fee_credited_once_to_zero_account: None,
                    disable_permanently_scilla_precompiles_v1: vec![],
                    deploy_escrow_mintable_contract_v1: None,
                    escrow_mintable_admin: None,
                    escrow_lodge_start_height: None,
                    escrow_lodge_file: None,
                    invalidate_zq1_staking_contract: None,
                    staked_zils_file: None,
                    restore_denylisted_accounts_v1: None,
                    remove_scilla_contracts_from_evm_delta: None,
                },
                ForkDelta {
                    at_height: 20,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: Some(false),
                    call_mode_1_sets_caller_to_parent_caller: Some(true),
                    scilla_messages_can_call_evm_contracts: Some(false),
                    scilla_contract_creation_increments_account_balance: Some(true),
                    scilla_json_preserve_order: Some(true),
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                    restore_ignite_wallet_contracts: None,
                    prevent_zil_transfer_from_evm_to_scilla_contract: None,
                    scilla_failed_txn_correct_gas_fee_charged: None,
                    check_minimum_gas_price: None,
                    inject_access_list: None,
                    use_max_gas_priority_fee: None,
                    failed_zil_transfers_to_eoa_proper_fee_deduction: None,
                    validator_jailing: None,
                    scilla_empty_maps_are_encoded_correctly: None,
                    cancun_active: None,
                    scilla_call_gas_exempt_addrs_v2: vec![],
                    randao_support: None,
                    evm_to_scilla_strings_encoded_properly: None,
                    dont_overwrite_evm_accounts_from_stale_scilla_state: None,
                    make_transfers_in_scilla_precompiles_with_journal_api: None,
                    disable_interop_native_zil_transfers_0: None,
                    tighten_precompile_rules: None,
                    allow_scilla_call_precompile_to_be_called_from_addresses: None,
                    distribute_rewards_every_epoch: None,
                    pectra_active: None,
                    disable_zilliqa_txn_execution: None,
                    blocked_recipients_start_height: None,
                    blocked_recipients_file: None,
                    blocked_recipients_start_height_v2: None,
                    blocked_recipients_file_v2: None,
                    blocked_recipients_start_height_v3: None,
                    blocked_recipients_file_v3: None,
                    blocked_recipients_start_height_v4: None,
                    blocked_recipients_file_v4: None,
                    zil_transfers_only_to_escrow: None,
                    deploy_escrow_contract_v1: None,
                    evm_gas_fee_credited_once_to_zero_account: None,
                    disable_permanently_scilla_precompiles_v1: vec![],
                    deploy_escrow_mintable_contract_v1: None,
                    escrow_mintable_admin: None,
                    escrow_lodge_start_height: None,
                    escrow_lodge_file: None,
                    invalidate_zq1_staking_contract: None,
                    staked_zils_file: None,
                    restore_denylisted_accounts_v1: None,
                    remove_scilla_contracts_from_evm_delta: None,
                },
            ],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 3);
        assert_eq!(forks.get(0).at_height, 0);
        assert_eq!(forks.get(11).at_height, 10);
        assert_eq!(forks.get(21).at_height, 20);
        assert!(
            forks
                .get(10)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
        assert!(forks.get(11).scilla_messages_can_call_evm_contracts);
        assert!(
            !forks
                .get(20)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
        assert!(forks.get(20).call_mode_1_sets_caller_to_parent_caller);
        assert!(!forks.get(20).scilla_messages_can_call_evm_contracts);
        assert!(
            forks
                .get(20)
                .scilla_contract_creation_increments_account_balance
        );
        assert!(forks.get(1).validator_jailing);
        assert!(!forks.get(11).validator_jailing);
        assert!(!forks.get(21).validator_jailing);
    }

    #[test]
    fn test_get_forks_with_unsorted_forks() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![
                ForkDelta {
                    at_height: 20,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: Some(false),
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                    restore_ignite_wallet_contracts: None,
                    prevent_zil_transfer_from_evm_to_scilla_contract: None,
                    scilla_failed_txn_correct_gas_fee_charged: None,
                    check_minimum_gas_price: None,
                    inject_access_list: None,
                    use_max_gas_priority_fee: None,
                    failed_zil_transfers_to_eoa_proper_fee_deduction: None,
                    validator_jailing: None,
                    scilla_empty_maps_are_encoded_correctly: None,
                    cancun_active: None,
                    scilla_call_gas_exempt_addrs_v2: vec![],
                    randao_support: None,
                    evm_to_scilla_strings_encoded_properly: None,
                    dont_overwrite_evm_accounts_from_stale_scilla_state: None,
                    make_transfers_in_scilla_precompiles_with_journal_api: None,
                    disable_interop_native_zil_transfers_0: None,
                    tighten_precompile_rules: None,
                    allow_scilla_call_precompile_to_be_called_from_addresses: None,
                    distribute_rewards_every_epoch: None,
                    pectra_active: None,
                    disable_zilliqa_txn_execution: None,
                    blocked_recipients_start_height: None,
                    blocked_recipients_file: None,
                    blocked_recipients_start_height_v2: None,
                    blocked_recipients_file_v2: None,
                    blocked_recipients_start_height_v3: None,
                    blocked_recipients_file_v3: None,
                    blocked_recipients_start_height_v4: None,
                    blocked_recipients_file_v4: None,
                    zil_transfers_only_to_escrow: None,
                    deploy_escrow_contract_v1: None,
                    evm_gas_fee_credited_once_to_zero_account: None,
                    disable_permanently_scilla_precompiles_v1: vec![],
                    deploy_escrow_mintable_contract_v1: None,
                    escrow_mintable_admin: None,
                    escrow_lodge_start_height: None,
                    escrow_lodge_file: None,
                    invalidate_zq1_staking_contract: None,
                    staked_zils_file: None,
                    restore_denylisted_accounts_v1: None,
                    remove_scilla_contracts_from_evm_delta: None,
                },
                ForkDelta {
                    at_height: 10,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                    restore_ignite_wallet_contracts: None,
                    prevent_zil_transfer_from_evm_to_scilla_contract: None,
                    scilla_failed_txn_correct_gas_fee_charged: None,
                    check_minimum_gas_price: None,
                    inject_access_list: None,
                    use_max_gas_priority_fee: None,
                    failed_zil_transfers_to_eoa_proper_fee_deduction: None,
                    validator_jailing: None,
                    scilla_empty_maps_are_encoded_correctly: None,
                    cancun_active: None,
                    scilla_call_gas_exempt_addrs_v2: vec![],
                    randao_support: None,
                    evm_to_scilla_strings_encoded_properly: None,
                    dont_overwrite_evm_accounts_from_stale_scilla_state: None,
                    make_transfers_in_scilla_precompiles_with_journal_api: None,
                    disable_interop_native_zil_transfers_0: None,
                    tighten_precompile_rules: None,
                    allow_scilla_call_precompile_to_be_called_from_addresses: None,
                    distribute_rewards_every_epoch: None,
                    pectra_active: None,
                    disable_zilliqa_txn_execution: None,
                    blocked_recipients_start_height: None,
                    blocked_recipients_file: None,
                    blocked_recipients_start_height_v2: None,
                    blocked_recipients_file_v2: None,
                    blocked_recipients_start_height_v3: None,
                    blocked_recipients_file_v3: None,
                    blocked_recipients_start_height_v4: None,
                    blocked_recipients_file_v4: None,
                    zil_transfers_only_to_escrow: None,
                    deploy_escrow_contract_v1: None,
                    evm_gas_fee_credited_once_to_zero_account: None,
                    disable_permanently_scilla_precompiles_v1: vec![],
                    deploy_escrow_mintable_contract_v1: None,
                    escrow_mintable_admin: None,
                    escrow_lodge_start_height: None,
                    escrow_lodge_file: None,
                    invalidate_zq1_staking_contract: None,
                    staked_zils_file: None,
                    restore_denylisted_accounts_v1: None,
                    remove_scilla_contracts_from_evm_delta: None,
                },
            ],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 3);
        assert_eq!(forks.get(0).at_height, 0);
        assert_eq!(forks.get(12).at_height, 10);
        assert_eq!(forks.get(22).at_height, 20);

        assert!(
            forks
                .get(10)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
        assert!(
            !forks
                .get(20)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
    }

    #[test]
    fn test_get_forks_with_missing_genesis_fork() {
        let config = ConsensusConfig {
            genesis_fork: Fork {
                at_height: 1,
                executable_blocks: true,
                failed_scilla_call_from_gas_exempt_caller_causes_revert: true,
                call_mode_1_sets_caller_to_parent_caller: true,
                scilla_messages_can_call_evm_contracts: true,
                scilla_contract_creation_increments_account_balance: true,
                scilla_json_preserve_order: true,
                scilla_call_respects_evm_state_changes: true,
                only_mutated_accounts_update_state: true,
                scilla_call_gas_exempt_addrs: vec![],
                scilla_block_number_returns_current_block: true,
                scilla_maps_are_encoded_correctly: true,
                transfer_gas_fee_to_zero_account: true,
                apply_scilla_delta_when_evm_succeeded: true,
                apply_state_changes_only_if_transaction_succeeds: true,
                scilla_deduct_funds_from_actual_sender: true,
                fund_accounts_from_zero_account: vec![],
                scilla_delta_maps_are_applied_correctly: true,
                scilla_server_unlimited_response_size: true,
                scilla_failed_txn_correct_balance_deduction: true,
                scilla_transition_proper_order: true,
                evm_to_scilla_value_transfer_zero: true,
                restore_xsgd_contract: true,
                evm_exec_failure_causes_scilla_precompile_to_fail: true,
                revert_restore_xsgd_contract: true,
                scilla_fix_contract_code_removal_on_evm_tx: true,
                restore_ignite_wallet_contracts: true,
                prevent_zil_transfer_from_evm_to_scilla_contract: true,
                scilla_failed_txn_correct_gas_fee_charged: true,
                check_minimum_gas_price: true,
                inject_access_list: true,
                use_max_gas_priority_fee: true,
                failed_zil_transfers_to_eoa_proper_fee_deduction: true,
                validator_jailing: true,
                scilla_empty_maps_are_encoded_correctly: true,
                cancun_active: true,
                scilla_call_gas_exempt_addrs_v2: vec![],
                randao_support: true,
                evm_to_scilla_strings_encoded_properly: true,
                dont_overwrite_evm_accounts_from_stale_scilla_state: true,
                make_transfers_in_scilla_precompiles_with_journal_api: true,
                disable_interop_native_zil_transfers_0: true,
                tighten_precompile_rules: true,
                allow_scilla_call_precompile_to_be_called_from_addresses: vec![],
                distribute_rewards_every_epoch: true,
                pectra_active: true,
                disable_zilliqa_txn_execution: true,
                blocked_recipients_start_height: 0,
                blocked_recipients_file: String::new(),
                blocked_recipients_start_height_v2: 0,
                blocked_recipients_file_v2: String::new(),
                blocked_recipients_start_height_v3: 0,
                blocked_recipients_file_v3: String::new(),
                blocked_recipients_start_height_v4: 0,
                blocked_recipients_file_v4: String::new(),
                zil_transfers_only_to_escrow: false,
                deploy_escrow_contract_v1: false,
                evm_gas_fee_credited_once_to_zero_account: false,
                disable_permanently_scilla_precompiles_v1: vec![],
                deploy_escrow_mintable_contract_v1: false,
                escrow_mintable_admin: Address::ZERO,
                escrow_lodge_start_height: 0,
                escrow_lodge_file: String::new(),
                invalidate_zq1_staking_contract: Address::ZERO,
                staked_zils_file: String::new(),
                restore_denylisted_accounts_v1: vec![],
                remove_scilla_contracts_from_evm_delta: false,
            },
            forks: vec![],
            ..Default::default()
        };

        let result = config.get_forks();
        assert!(result.is_err());
    }

    #[test]
    fn test_get_forks_boundary_cases() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![
                ForkDelta {
                    at_height: 10,
                    executable_blocks: None,
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                    restore_ignite_wallet_contracts: None,
                    prevent_zil_transfer_from_evm_to_scilla_contract: None,
                    scilla_failed_txn_correct_gas_fee_charged: None,
                    check_minimum_gas_price: None,
                    inject_access_list: None,
                    use_max_gas_priority_fee: None,
                    failed_zil_transfers_to_eoa_proper_fee_deduction: None,
                    validator_jailing: None,
                    scilla_empty_maps_are_encoded_correctly: None,
                    cancun_active: None,
                    scilla_call_gas_exempt_addrs_v2: vec![],
                    randao_support: None,
                    evm_to_scilla_strings_encoded_properly: None,
                    dont_overwrite_evm_accounts_from_stale_scilla_state: None,
                    make_transfers_in_scilla_precompiles_with_journal_api: None,
                    disable_interop_native_zil_transfers_0: None,
                    tighten_precompile_rules: None,
                    allow_scilla_call_precompile_to_be_called_from_addresses: None,
                    distribute_rewards_every_epoch: None,
                    pectra_active: None,
                    disable_zilliqa_txn_execution: None,
                    blocked_recipients_start_height: None,
                    blocked_recipients_file: None,
                    blocked_recipients_start_height_v2: None,
                    blocked_recipients_file_v2: None,
                    blocked_recipients_start_height_v3: None,
                    blocked_recipients_file_v3: None,
                    blocked_recipients_start_height_v4: None,
                    blocked_recipients_file_v4: None,
                    zil_transfers_only_to_escrow: None,
                    deploy_escrow_contract_v1: None,
                    evm_gas_fee_credited_once_to_zero_account: None,
                    disable_permanently_scilla_precompiles_v1: vec![],
                    deploy_escrow_mintable_contract_v1: None,
                    escrow_mintable_admin: None,
                    escrow_lodge_start_height: None,
                    escrow_lodge_file: None,
                    invalidate_zq1_staking_contract: None,
                    staked_zils_file: None,
                    restore_denylisted_accounts_v1: None,
                    remove_scilla_contracts_from_evm_delta: None,
                },
                ForkDelta {
                    at_height: 20,
                    executable_blocks: None,
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                    restore_ignite_wallet_contracts: None,
                    prevent_zil_transfer_from_evm_to_scilla_contract: None,
                    scilla_failed_txn_correct_gas_fee_charged: None,
                    check_minimum_gas_price: None,
                    inject_access_list: None,
                    use_max_gas_priority_fee: None,
                    failed_zil_transfers_to_eoa_proper_fee_deduction: None,
                    validator_jailing: None,
                    scilla_empty_maps_are_encoded_correctly: None,
                    cancun_active: None,
                    scilla_call_gas_exempt_addrs_v2: vec![],
                    randao_support: None,
                    evm_to_scilla_strings_encoded_properly: None,
                    dont_overwrite_evm_accounts_from_stale_scilla_state: None,
                    make_transfers_in_scilla_precompiles_with_journal_api: None,
                    disable_interop_native_zil_transfers_0: None,
                    tighten_precompile_rules: None,
                    allow_scilla_call_precompile_to_be_called_from_addresses: None,
                    distribute_rewards_every_epoch: None,
                    pectra_active: None,
                    disable_zilliqa_txn_execution: None,
                    blocked_recipients_start_height: None,
                    blocked_recipients_file: None,
                    blocked_recipients_start_height_v2: None,
                    blocked_recipients_file_v2: None,
                    blocked_recipients_start_height_v3: None,
                    blocked_recipients_file_v3: None,
                    blocked_recipients_start_height_v4: None,
                    blocked_recipients_file_v4: None,
                    zil_transfers_only_to_escrow: None,
                    deploy_escrow_contract_v1: None,
                    evm_gas_fee_credited_once_to_zero_account: None,
                    disable_permanently_scilla_precompiles_v1: vec![],
                    deploy_escrow_mintable_contract_v1: None,
                    escrow_mintable_admin: None,
                    escrow_lodge_start_height: None,
                    escrow_lodge_file: None,
                    invalidate_zq1_staking_contract: None,
                    staked_zils_file: None,
                    restore_denylisted_accounts_v1: None,
                    remove_scilla_contracts_from_evm_delta: None,
                },
            ],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.get(9).at_height, 0);
        assert_eq!(forks.get(10).at_height, 10);
        assert_eq!(forks.get(19).at_height, 10);
        assert_eq!(forks.get(20).at_height, 20);
        assert_eq!(forks.get(22).at_height, 20);
    }
}
