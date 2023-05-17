use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The port to listen for P2P messages on. Optional - If not provided a random port will be used.
    pub p2p_port: Option<u16>,
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    #[serde(default = "default_json_rpc_port")]
    pub json_rpc_port: u16,
    #[serde(default = "default_eth_chain_id")]
    pub eth_chain_id: u64,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    pub otlp_collector_endpoint: Option<String>,
    /// The maximum duration between a recieved block's timestamp and the current time. Defaults to 10 seconds.
    #[serde(default = "default_allowed_timestamp_skew")]
    pub allowed_timestamp_skew: Duration,
}

fn default_json_rpc_port() -> u16 {
    4201
}

fn default_eth_chain_id() -> u64 {
    1 + 0x8000
}

fn default_allowed_timestamp_skew() -> Duration {
    Duration::from_secs(10)
}
