use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The port to listen for P2P messages on. Optional - If not provided a random port will be used.
    pub p2p_port: Option<u16>,
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    #[serde(default = "default_json_rpc_port")]
    pub json_rpc_port: u16,
}

fn default_json_rpc_port() -> u16 {
    4201
}
