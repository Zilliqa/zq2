use clap::Args;
use merge::Merge;
use serde::Deserialize;

/// Helper struct used for deserializing the config file and parsing command line arguments.
/// Fields must match Config struct, but every field should be optional.
#[derive(Debug, Clone, Default, Deserialize, Args, Merge)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigOpt {
    #[clap(long)]
    pub p2p_port: Option<u16>,
    #[clap(long)]
    pub json_rpc_port: Option<u16>,
    #[clap(long)]
    pub disable_json_rpc: Option<bool>,
    #[clap(long)]
    pub eth_chain_id: Option<u64>,
    #[clap(long)]
    pub otlp_collector_endpoint: Option<String>,
    #[clap(long)]
    pub allowed_timestamp_skew: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// The port to listen for P2P messages on. 0 means random.
    pub p2p_port: u16,
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    pub json_rpc_port: u16,
    /// Pass this to disable listening to JSON-RPC requests entirely.
    pub disable_json_rpc: bool,
    pub eth_chain_id: u64,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    pub otlp_collector_endpoint: Option<String>,
    /// The maximum duration between a recieved block's timestamp and the current time, in seconds.
    pub allowed_timestamp_skew: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            p2p_port: 0,
            json_rpc_port: 4201,
            disable_json_rpc: false,
            eth_chain_id: 2 + 0x8000,
            otlp_collector_endpoint: None,
            allowed_timestamp_skew: 10,
        }
    }
}
