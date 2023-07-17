use std::time::Duration;

use serde::Deserialize;

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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            p2p_port: 0,
            json_rpc_port: 4201,
            eth_chain_id: 1 + 0x8000,
            otlp_collector_endpoint: None,
            allowed_timestamp_skew: Duration::from_secs(10),
            data_dir: Some("zq2data".to_string()),
        }
    }
}
