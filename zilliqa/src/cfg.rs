use std::{ops::Deref, str::FromStr, time::Duration};

use alloy_primitives::Address;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{crypto::NodePublicKey, transaction::EvmGas};

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
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    #[serde(default = "json_rcp_port_default")]
    pub json_rpc_port: u16,
    /// If true, the JSON-RPC server is not started. Defaults to false.
    #[serde(default = "disable_rpc_default")]
    pub disable_rpc: bool,
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
    /// The maximum number of blocks we will send to another node in a single message.
    #[serde(default = "block_request_limit_default")]
    pub block_request_limit: usize,
    /// The maximum number of blocks to have outstanding requests for at a time when syncing.
    #[serde(default = "max_blocks_in_flight_default")]
    pub max_blocks_in_flight: u64,
    /// The maximum number of blocks to request in a single message when syncing.
    #[serde(default = "block_request_batch_size_default")]
    pub block_request_batch_size: u64,
}

pub fn allowed_timestamp_skew_default() -> Duration {
    Duration::from_secs(10)
}

pub fn json_rcp_port_default() -> u16 {
    4201
}

pub fn eth_chain_id_default() -> u64 {
    700 + 0x8000
}

pub fn disable_rpc_default() -> bool {
    false
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
    pub genesis_deposits: Vec<(NodePublicKey, PeerId, Amount, Address)>,
    /// Accounts that will be pre-funded at genesis.
    #[serde(default)]
    pub genesis_accounts: Vec<(Address, Amount)>,
    /// Minimum time to wait for consensus to propose new block if there are no transactions.
    #[serde(default = "empty_block_timeout_default")]
    pub empty_block_timeout: Duration,
    /// Minimum remaining time allowing to wait for empty block proposal
    #[serde(default = "minimum_time_left_for_empty_block_default")]
    pub minimum_time_left_for_empty_block: Duration,
    /// Address of the Scilla server. Defaults to "http://localhost:3000".
    #[serde(default = "scilla_address_default")]
    pub scilla_address: String,
    /// Where (in the Scilla server's filesystem) is the library directory containing Scilla library functions?
    #[serde(default = "scilla_lib_dir_default")]
    pub scilla_lib_dir: String,
    /// Hostname at which this process is accessible by the Scilla process. Defaults to "localhost". If running the
    /// Scilla process in Docker and this process on the host, you probably want to pass
    /// `--add-host host.docker.internal:host-gateway` to Docker and set this to `host.docker.internal`.
    #[serde(default = "local_address_default")]
    pub local_address: String,
    pub rewards_per_hour: Amount,
    pub blocks_per_hour: u64,
    pub minimum_stake: Amount,
    pub eth_block_gas_limit: EvmGas,
    pub gas_price: Amount,
}

pub fn consensus_timeout_default() -> Duration {
    Duration::from_secs(5)
}

pub fn empty_block_timeout_default() -> Duration {
    Duration::from_millis(1000)
}

pub fn minimum_time_left_for_empty_block_default() -> Duration {
    Duration::from_millis(3000)
}

pub fn scilla_address_default() -> String {
    String::from("http://localhost:3000")
}

pub fn scilla_lib_dir_default() -> String {
    String::from("/scilla/0/_build/default/src/stdlib/")
}

pub fn local_address_default() -> String {
    String::from("localhost")
}

fn default_true() -> bool {
    true
}
