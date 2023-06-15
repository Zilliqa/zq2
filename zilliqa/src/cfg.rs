use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Args)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The port to listen for P2P messages on. 0 means random.
    #[clap(long, required = false)]
    pub p2p_port: u16,
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    #[clap(long, default_value = "4201")]
    pub json_rpc_port: u16,
    /// Pass this to disable listening to JSON-RPC requests entirely.
    #[clap(long, default_value = "false")]
    pub disable_json_rpc: bool,
    #[clap(long, required = false)] // 32768 + 1 = 0x8000 + 1
    pub eth_chain_id: u64,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    #[clap(long)]
    pub otlp_collector_endpoint: Option<String>,
    /// The maximum duration between a recieved block's timestamp and the current time, in seconds.
    #[clap(long, default_value = "10")]
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
