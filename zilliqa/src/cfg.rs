use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{Hash, NodePublicKey},
    state::Address,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Individual configuration for every node to run.
    pub nodes: Vec<NodeConfig>,
    /// The port to listen for P2P messages on. Optional - If not provided a random port will be used.
    pub p2p_port: u16,
    /// The address of another node to dial when this node starts. To join the network, a node must know about at least
    /// one other existing node in the network.
    pub bootstrap_address: Option<(PeerId, Multiaddr)>,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    pub otlp_collector_endpoint: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            nodes: vec![NodeConfig::default()],
            bootstrap_address: None,
            p2p_port: 0,
            otlp_collector_endpoint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    pub json_rpc_port: u16,
    /// If true, the JSON-RPC server is not started. Defaults to false.
    pub disable_rpc: bool,
    /// Chain identifier. Doubles as shard_id internally.
    pub eth_chain_id: u64,
    /// Consensus-specific data.
    pub consensus: ConsensusConfig,
    /// The maximum duration between a recieved block's timestamp and the current time. Defaults to 10 seconds.
    pub allowed_timestamp_skew: Duration,
    /// The location of persistence data. If not set, uses a temporary path.
    pub data_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsensusConfig {
    /// If main, deploy a shard registry contract.
    pub is_main: bool,
    /// If not main, parent main shard.
    pub main_shard_id: Option<u64>,
    /// The maximum time to wait for consensus to proceed as normal, before proposing a new view.
    pub consensus_timeout: Duration,
    /// The genesis committee (public key, peer id) pairs. Only allowed to have one member at the moment
    /// Genesis data. Specifying a committee node is necessary for nodes participating in the consensus at
    /// genesis. Only the hash can be specified for nodes joining afterwards.
    pub genesis_committee: Vec<(NodePublicKey, PeerId)>,
    /// The initially staked deposits in the deposit contract at genesis, composed of
    /// (public key, amount, reward address) tuples.
    pub genesis_deposits: Vec<(NodePublicKey, String, Address)>,
    pub genesis_hash: Option<Hash>,
    /// Accounts that will be pre-funded at genesis.
    pub genesis_accounts: Vec<(Address, String)>,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            is_main: true,
            main_shard_id: None,
            consensus_timeout: Duration::from_secs(5),
            genesis_committee: vec![],
            genesis_deposits: vec![],
            genesis_hash: None,
            genesis_accounts: Vec::new(),
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            json_rpc_port: 4201,
            disable_rpc: false,
            consensus: Default::default(),
            // Default to the "Zilliqa local development" chain ID.
            eth_chain_id: 700 + 0x8000,
            allowed_timestamp_skew: Duration::from_secs(10),
            data_dir: None,
        }
    }
}
