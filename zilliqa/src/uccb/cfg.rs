use crate::crypto::SecretKey;
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
    pub rpc_url: String,
    pub chain_gateway_address: Address,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub zq2: ZQ2Config,
    pub chain_configs: Vec<ChainConfig>,
}
