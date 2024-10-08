use alloy::primitives::Address;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZQ2Config {
    pub rpc_url: String,
    pub chain_gateway_address: Address,
    pub validator_manager_address: Address,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    // Must be ws:// to support subscriptions.
    pub rpc_url: String,
    #[serde(default)]
    pub estimate_gas: bool,
    #[serde(default)]
    pub legacy_gas_estimation: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub max_dispatch_attempts: u8,
    pub zq2: ZQ2Config,
    pub chain_configs: Vec<ChainConfig>,
}
