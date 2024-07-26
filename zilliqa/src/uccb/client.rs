use std::sync::Arc;

use alloy_network::Ethereum;
use alloy_primitives::Address;
use alloy_provider::fillers::*;
use alloy_provider::{Identity, Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy_pubsub::PubSubFrontend;

use anyhow::Result;
use ethers::{
    signers::LocalWallet,
    // types::{Address, U256},
};

use crate::uccb::cfg::ChainConfig;

// pub type Client =
// NonceManagerMiddleware<SignerMiddleware<ethers::providers::Provider<Ws>, LocalWallet>>;
pub type ChainProvider = FillProvider<
    JoinFill<JoinFill<JoinFill<Identity, GasFiller>, NonceFiller>, ChainIdFiller>,
    RootProvider<PubSubFrontend>,
    PubSubFrontend,
    Ethereum,
>;

#[derive(Debug, Clone)]
pub struct ChainClient {
    pub rpc_url: String,
    pub client: Arc<ChainProvider>,
    pub validator_manager_address: Address,
    // pub chain_gateway_address: Address,
    pub chain_id: u64,
    pub wallet: LocalWallet,
    pub chain_gateway_block_deployed: u64,
    pub block_instant_finality: bool,
    pub legacy_gas_estimation: bool,
}

impl ChainClient {
    pub async fn new(
        config: &ChainConfig,
        validator_manager_address: Address,
        // chain_gateway_address: Address,
        wallet: LocalWallet,
    ) -> Result<Self> {
        let ws = WsConnect::new(&config.rpc_url);
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_ws(ws)
            .await?;
        let chain_id = provider.get_chain_id().await?;
        let client: Arc<ChainProvider> = Arc::new(provider);

        // TODO: get the validator_manager_address from chain_gateway itself
        // let chain_gateway = ChainGateway::new(config.chain_gateway_address, client.clone());
        // let validator_manager_address: Address = chain_gateway.validator_manager().call().await?;

        Ok(ChainClient {
            rpc_url: config.rpc_url.clone(),
            client,
            validator_manager_address,
            // chain_gateway_address,
            chain_id,
            wallet,
            chain_gateway_block_deployed: config.chain_gateway_block_deployed,
            block_instant_finality: config.block_instant_finality.unwrap_or_default(),
            legacy_gas_estimation: config.legacy_gas_estimation.unwrap_or_default(),
        })
    }
}
