use clap::Args;
use merge::num::overwrite_zero;
use merge::Merge;
use serde::Deserialize;

// NOTE: The clap default values here are meant to be overwritten using merge::Merge, after the
// config file is parsed.
// Specify new configuration options with an overwritable default value.
#[derive(Debug, Clone, Deserialize, Args, Merge)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The port to listen for P2P messages on. 0 means random.
    #[clap(long, default_value = "0")]
    #[merge(strategy = overwrite_zero)]
    pub p2p_port: u16,
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    #[clap(long, default_value = "0")]
    #[merge(strategy = overwrite_zero)]
    pub json_rpc_port: u16,
    /// Pass this to disable listening to JSON-RPC requests entirely.
    /// Command line only.
    #[clap(long, default_value = "false")]
    #[serde(skip)]
    #[merge(skip)]
    pub disable_json_rpc: bool,
    #[clap(long, default_value = "0")]
    #[merge(strategy = overwrite_zero)]
    pub eth_chain_id: u64,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    #[clap(long)]
    pub otlp_collector_endpoint: Option<String>,
    /// The maximum duration between a recieved block's timestamp and the current time, in seconds.
    #[clap(long, default_value = "0")]
    #[merge(strategy = overwrite_zero)]
    pub allowed_timestamp_skew: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            p2p_port: 0,
            json_rpc_port: 4201,
            disable_json_rpc: false,
            eth_chain_id: 1 + 0x8000,
            otlp_collector_endpoint: None,
            allowed_timestamp_skew: 10,
        }
    }
}
