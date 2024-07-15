use crate::crypto::SecretKey;
use alloy_primitives::Address;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct ValidatorNodeConfig {
    pub zq2: ZQ2Config,
    pub chain_configs: Vec<ChainConfig>,
    pub private_key: SecretKey,
    pub is_leader: bool,
    // pub bootstrap_address: Option<(PeerId, Multiaddr)>,
}

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
    pub chain_gateway_block_deployed: u64,
    pub block_instant_finality: Option<bool>,
    pub legacy_gas_estimation: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub zq2: ZQ2Config,
    pub chain_configs: Vec<ChainConfig>,
}
