use std::{str::FromStr, time::Duration};

use alloy_primitives::Address;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    crypto::{Hash, NodePublicKey},
    transaction::EvmGas,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Individual configuration for every node to run.
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
    /// The port to listen for P2P messages on. Optional - If not provided a random port will be used.
    #[serde(default)]
    pub p2p_port: u16,
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
    pub genesis_deposits: Vec<(NodePublicKey, PeerId, String, Address)>,
    #[serde(default)]
    pub genesis_hash: Option<Hash>,
    /// Accounts that will be pre-funded at genesis.
    #[serde(default)]
    pub genesis_accounts: Vec<(Address, String)>,
    /// Minimum time to wait for consensus to propose new block if there are no transactions.
    #[serde(default = "minimum_time_left_for_empty_block_default")]
    pub empty_block_timeout: Duration,
    /// Minimum remaining time allowing to wait for empty block proposal
    #[serde(default = "empty_block_timeout_default")]
    pub minimum_time_left_for_empty_block: Duration,
    /// Address of the Scilla server. Defaults to "http://localhost:3000".
    #[serde(default = "scilla_address_default")]
    pub scilla_address: String,
    /// Hostname at which this process is accessible by the Scilla process. Defaults to "localhost". If running the
    /// Scilla process in Docker and this process on the host, you probably want to pass
    /// `--add-host host.docker.internal:host-gateway` to Docker and set this to `host.docker.internal`.
    #[serde(default = "local_address_default")]
    pub local_address: String,
    // Keep the following fields as optionals - they don't have default values and have to be explicitly specified
    #[serde(deserialize_with = "str_to_u128")]
    pub rewards_per_hour: u128,
    pub blocks_per_hour: u64,
    #[serde(deserialize_with = "str_to_u128")]
    pub minimum_stake: u128,
    pub eth_block_gas_limit: EvmGas,
    #[serde(deserialize_with = "str_to_u128")]
    pub gas_price: u128,
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

pub fn local_address_default() -> String {
    String::from("localhost")
}

fn default_true() -> bool {
    true
}

fn str_to_u128<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    let res = String::deserialize(deserializer)?;
    let res = res.replace('_', "");
    Ok(u128::from_str(&res).unwrap())
}
