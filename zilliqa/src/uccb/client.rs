use std::sync::Arc;

// use crate::{ChainGateway, ValidatorManager};
use crate::uccb::cfg::ChainConfig;
use anyhow::Result;
use ethers::{
    middleware::{MiddlewareBuilder, NonceManagerMiddleware, SignerMiddleware},
    providers::{Middleware, Provider, Ws},
    signers::{LocalWallet, Signer},
    types::{Address, U256},
};

pub type Client = NonceManagerMiddleware<SignerMiddleware<Provider<Ws>, LocalWallet>>;

#[derive(Debug, Clone)]
pub struct ChainClient {
    pub client: Arc<Client>,
    pub validator_manager_address: Address,
    // pub chain_gateway_address: Address,
    pub chain_id: U256,
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
        // let provider = Provider::<Http>::try_from(config.rpc_url.as_str())?;
        let ws = Ws::connect(&config.rpc_url).await?;
        let provider = ethers::providers::Provider::<Ws>::new(ws);
        let chain_id = provider.get_chainid().await?;

        let client: Arc<Client> = Arc::new(
            provider
                .with_signer(wallet.clone().with_chain_id(chain_id.as_u64()))
                .nonce_manager(wallet.address()),
        );

        // TODO: get the validator_manager_address from chain_gateway itself
        // let chain_gateway = ChainGateway::new(config.chain_gateway_address, client.clone());
        // let validator_manager_address: Address = chain_gateway.validator_manager().call().await?;

        Ok(ChainClient {
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
