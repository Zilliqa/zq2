use alloy::primitives::Address;
use serde::Deserialize;
use zilliqa::crypto::SecretKey;

#[derive(Debug, Clone)]
pub struct ValidatorNodeConfig {
    pub zq2: ZQ2Config,
    pub chain_configs: Vec<ChainConfig>,
    pub private_key: SecretKey,
    pub is_leader: bool,
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
    #[serde(default)]
    pub block_instant_finality: bool,
    #[serde(default)]
    pub legacy_gas_estimation: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub zq2: ZQ2Config,
    pub chain_configs: Vec<ChainConfig>,
}
