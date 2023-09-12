use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::{crypto::NodePublicKey, state::Address};

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
    pub eth_chain_id: u64,
    /// The maximum duration between a recieved block's timestamp and the current time. Defaults to 10 seconds.
    pub allowed_timestamp_skew: Duration,
    /// The location of persistence data. If not set, uses a temporary path.
    pub data_dir: Option<String>,
    /// The maximum time to wait for consensus to proceed as normal, before proposing a new view.
    pub consensus_timeout: Duration,
    /// The maximum number of times to retry out of order TXs before dropping them
    pub tx_retries: u64,
    /// The genesis committee (public key, peer id) pairs. Only allowed to have one member at the moment
    pub genesis_committee: Vec<(NodePublicKey, PeerId)>,
    pub genesis_accounts: Vec<(Address, String)>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            json_rpc_port: 4201,
            disable_rpc: false,
            // Default to the "Zilliqa local development" chain ID.
            eth_chain_id: 700 + 0x8000,
            allowed_timestamp_skew: Duration::from_secs(10),
            data_dir: None,
            consensus_timeout: Duration::from_secs(5),
            tx_retries: 1000,
            genesis_committee: vec![],
            genesis_accounts: Vec::new(),
        }
    }
}
