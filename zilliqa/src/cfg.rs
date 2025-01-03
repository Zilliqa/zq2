use std::{ops::Deref, str::FromStr, time::Duration};

use alloy::primitives::Address;
use anyhow::{anyhow, Result};
use libp2p::{Multiaddr, PeerId};
use rand::{distributions::Alphanumeric, Rng};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;

use crate::{
    crypto::{Hash, NodePublicKey},
    transaction::EvmGas,
};

// Note that z2 constructs instances of this to save as a configuration so it must be both
// serializable and deserializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
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
    pub bootstrap_address: Option<(PeerId, Multiaddr)>,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    #[serde(default)]
    pub otlp_collector_endpoint: Option<String>,
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
    /// The maximum number of blocks to have outstanding requests for at a time when syncing.
    #[serde(default = "max_blocks_in_flight_default")]
    pub max_blocks_in_flight: u64,
    /// The maximum number of blocks to request in a single message when syncing.
    #[serde(default = "block_request_batch_size_default")]
    pub block_request_batch_size: u64,
    /// The maximum number of key value pairs allowed to be returned withing the response of the `GetSmartContractState` RPC. Defaults to no limit.
    #[serde(default = "state_rpc_limit_default")]
    pub state_rpc_limit: usize,
    /// When a block request to a peer fails, do not send another request to this peer for this amount of time.
    /// Defaults to 10 seconds.
    #[serde(default = "failed_request_sleep_duration_default")]
    pub failed_request_sleep_duration: Duration,
    /// Enable additional indices used by some Otterscan APIs. Enabling this will use more disk space and block processing will take longer.
    #[serde(default)]
    pub enable_ots_indices: bool,
    /// Maximum allowed RPC response size
    #[serde(default = "max_rpc_response_size_default")]
    pub max_rpc_response_size: u32,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            api_servers: vec![],
            eth_chain_id: eth_chain_id_default(),
            consensus: ConsensusConfig::default(),
            allowed_timestamp_skew: allowed_timestamp_skew_default(),
            data_dir: None,
            state_cache_size: state_cache_size_default(),
            load_checkpoint: None,
            do_checkpoints: false,
            block_request_limit: block_request_limit_default(),
            max_blocks_in_flight: max_blocks_in_flight_default(),
            block_request_batch_size: block_request_batch_size_default(),
            state_rpc_limit: state_rpc_limit_default(),
            failed_request_sleep_duration: failed_request_sleep_duration_default(),
            enable_ots_indices: false,
            max_rpc_response_size: max_rpc_response_size_default(),
        }
    }
}

impl NodeConfig {
    pub fn validate(&self) -> Result<()> {
        if let serde_json::Value::Object(map) =
            serde_json::to_value(self.consensus.contract_upgrade_block_heights.clone())?
        {
            for (contract, block_height) in map {
                if block_height.as_u64().unwrap_or(0) % self.consensus.blocks_per_epoch != 0 {
                    return Err(anyhow!("Contract upgrades must be configured to occur at epoch boundaries. blocks_per_epoch: {}, contract {} configured to be upgraded block: {}", self.consensus.blocks_per_epoch, contract, block_height));
                }
            }
        }
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

pub fn allowed_timestamp_skew_default() -> Duration {
    Duration::from_secs(60)
}

pub fn state_cache_size_default() -> usize {
    256 * 1024 * 1024 // 256 MiB
}

pub fn eth_chain_id_default() -> u64 {
    700 + 0x8000
}

pub fn block_request_limit_default() -> usize {
    100
}

pub fn max_blocks_in_flight_default() -> u64 {
    1000
}

pub fn block_request_batch_size_default() -> u64 {
    100
}

pub fn max_rpc_response_size_default() -> u32 {
    10 * 1024 * 1024 // 10 MB
}

pub fn state_rpc_limit_default() -> usize {
    // isize maximum because toml serialisation supports i64 integers
    isize::MAX as usize
}

pub fn failed_request_sleep_duration_default() -> Duration {
    Duration::from_secs(10)
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
    /// Address of the Scilla server. Defaults to "http://localhost:3000".
    #[serde(default = "scilla_address_default")]
    pub scilla_address: String,
    /// Where (in the Scilla server's filesystem) is the library directory containing Scilla library functions?
    #[serde(default = "scilla_stdlib_dir_default")]
    pub scilla_stdlib_dir: String,
    /// Where are the external libraries are stored on zq2 and scilla server's filesystem so that scilla server can find them?
    #[serde(default = "scilla_ext_libs_path_default")]
    pub scilla_ext_libs_path: ScillaExtLibsPath,
    /// Hostname at which this process is accessible by the Scilla process. Defaults to "localhost". If running the
    /// Scilla process in Docker and this process on the host, you probably want to pass
    /// `--add-host host.docker.internal:host-gateway` to Docker and set this to `host.docker.internal`.
    #[serde(default = "local_address_default")]
    pub local_address: String,
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
    /// Calls to the `scilla_call` precompile from these addresses cost a different amount of gas. If the provided gas
    /// limit is not enough, the call will still succeed and we will charge as much gas as we can. This hack exists due
    /// to important contracts deployed on Zilliqa 1's mainnet that pass the incorrect gas limit to `scilla_call`.
    /// Zilliqa 1's implementation was broken and accepted these calls and these contracts are now widely used and
    /// bridged to other chains.
    #[serde(default)]
    pub scilla_call_gas_exempt_addrs: Vec<Address>,
    /// The block heights at which we perform EIP-1967 contract upgrades
    /// Contract upgrades occur only at epoch boundaries, ie at block heights which are a multiple of blocks_per_epoch
    #[serde(default)]
    pub contract_upgrade_block_heights: ContractUpgradesBlockHeights,
    /// Forks in block execution logic. Each entry describes the difference in logic and the block height at which that
    /// difference applies.
    #[serde(default)]
    pub forks: Forks,
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
            local_address: local_address_default(),
            rewards_per_hour: 204_000_000_000_000_000_000_000u128.into(),
            blocks_per_hour: 3600 * 40,
            minimum_stake: 32_000_000_000_000_000_000u128.into(),
            eth_block_gas_limit: EvmGas(84000000),
            blocks_per_epoch: blocks_per_epoch_default(),
            epochs_per_checkpoint: epochs_per_checkpoint_default(),
            gas_price: 4_761_904_800_000u128.into(),
            total_native_token_supply: total_native_token_supply_default(),
            scilla_call_gas_exempt_addrs: vec![],
            contract_upgrade_block_heights: ContractUpgradesBlockHeights::default(),
            forks: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "Vec<Fork>", into = "Vec<Fork>")]
pub struct Forks(Vec<Fork>);

impl TryFrom<Vec<Fork>> for Forks {
    type Error = anyhow::Error;

    fn try_from(mut forks: Vec<Fork>) -> Result<Self, Self::Error> {
        // Sort forks by height so we can binary search to find the current fork.
        forks.sort_unstable_by_key(|f| f.at_height);

        // Assert we have a fork that starts at the genesis block.
        if forks.first().ok_or_else(|| anyhow!("no forks"))?.at_height != 0 {
            return Err(anyhow!("first fork must start at height 0"));
        }

        Ok(Forks(forks))
    }
}

impl From<Forks> for Vec<Fork> {
    fn from(forks: Forks) -> Self {
        forks.0
    }
}

impl Default for Forks {
    /// The default implementation of [Forks] returns a single fork at the genesis block, with the most up-to-date
    /// execution logic.
    fn default() -> Self {
        vec![Fork {
            at_height: 0,
            failed_scilla_call_from_gas_exempt_caller_causes_revert: true,
            call_mode_1_sets_caller_to_parent_caller: true,
        }]
        .try_into()
        .unwrap()
    }
}

impl Forks {
    pub fn get(&self, height: u64) -> Fork {
        // Binary search to find the fork at the specified height. If an entry was not found at exactly the specified
        // height, the `Err` returned from `binary_search_by_key` will contain the index where an element with this
        // height could be inserted. By subtracting one from this, we get the maximum entry with a height less than the
        // searched height.
        let index = self
            .0
            .binary_search_by_key(&height, |f| f.at_height)
            .unwrap_or_else(|i| i - 1);
        self.0[index]
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Fork {
    pub at_height: u64,
    /// If true, if a caller who is in the `scilla_call_gas_exempt_addrs` list makes a call to the `scilla_call`
    /// precompile and the inner Scilla call fails, the entire transaction will revert. If false, the normal EVM
    /// semantics apply where the caller can decide how to act based on the success of the inner call.
    pub failed_scilla_call_from_gas_exempt_caller_causes_revert: bool,
    /// If true, if a call is made to the `scilla_call` precompile with `call_mode` / `keep_origin` set to `1`, the
    /// `_sender` of the inner Scilla call will be set to the caller of the current call-stack. If false, the `_sender`
    /// will be set to the original transaction signer.
    ///
    /// For example:
    /// A (EOA) -> B (EVM) -> C (EVM) -> D (Scilla)
    ///
    /// When this flag is true, `D` will see the `_sender` as `B`. When this flag is false, `D` will see the `_sender`
    /// as `A`.
    pub call_mode_1_sets_caller_to_parent_caller: bool,
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
    Duration::from_secs(5)
}

pub fn block_time_default() -> Duration {
    Duration::from_millis(1000)
}

pub fn scilla_address_default() -> String {
    String::from("http://localhost:3000")
}

// This path is as viewed from Scilla, not zq2.
pub fn scilla_stdlib_dir_default() -> String {
    String::from("/scilla/0/_build/default/src/stdlib/")
}

pub fn scilla_ext_libs_path_default() -> ScillaExtLibsPath {
    ScillaExtLibsPath {
        zq2: ScillaExtLibsPathInZq2(String::from("/tmp")),
        scilla: ScillaExtLibsPathInScilla(String::from("/scilla_ext_libs")),
    }
}

pub fn local_address_default() -> String {
    String::from("localhost")
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractUpgradesBlockHeights {
    pub deposit_v3: Option<u64>,
}

impl ContractUpgradesBlockHeights {
    // toml doesnt like Option types. Map items in struct and remove keys for None values
    pub fn to_toml(&self) -> toml::Value {
        toml::Value::Table(
            json!(self)
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .filter_map(|(k, v)| {
                    if v.is_null() {
                        None // Skip null values
                    } else {
                        Some((k, toml::Value::Integer(v.as_u64().unwrap() as i64)))
                    }
                })
                .collect(),
        )
    }
}
