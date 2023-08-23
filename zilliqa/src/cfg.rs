use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use serde::Deserialize;

use crate::crypto::NodePublicKey;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The port to listen for P2P messages on. Optional - If not provided a random port will be used.
    pub p2p_port: u16,
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    pub json_rpc_port: u16,
    pub eth_chain_id: u64,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    pub otlp_collector_endpoint: Option<String>,
    /// The maximum duration between a recieved block's timestamp and the current time. Defaults to 10 seconds.
    pub allowed_timestamp_skew: Duration,
    /// The location of persistence data. If not set, uses a temporary path.
    pub data_dir: Option<String>,
    /// The maximum time to wait for consensus to proceed as normal, before proposing a new view.
    pub consensus_timeout: Duration,
    /// The address of another node to dial when this node starts. To join the network, a node must know about at least
    /// one other existing node in the network.
    pub bootstrap_address: Option<(PeerId, Multiaddr)>,
    pub genesis_committee: Vec<(NodePublicKey, PeerId)>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            p2p_port: 0,
            json_rpc_port: 4201,
            eth_chain_id: 1 + 0x8000,
            otlp_collector_endpoint: None,
            allowed_timestamp_skew: Duration::from_secs(10),
            data_dir: None,
            consensus_timeout: Duration::from_secs(5),
            bootstrap_address: None,
            genesis_committee: vec![],
        }
    }
}
