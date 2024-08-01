use crate::uccb::cfg::ChainConfig;
use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::Address,
    providers::{fillers::*, Identity, Provider, ProviderBuilder, RootProvider, WsConnect},
    pubsub::PubSubFrontend,
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use std::sync::Arc;

pub type ChainProvider = FillProvider<
    JoinFill<
        JoinFill<JoinFill<JoinFill<Identity, ChainIdFiller>, GasFiller>, NonceFiller>,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<PubSubFrontend>,
    PubSubFrontend,
    Ethereum,
>;

/*
pub type ChainProvider = FillProvider<
    JoinFill<
        JoinFill<
            JoinFill<JoinFill<Identity, ChainIdFiller>, NonceFiller>,
            ChainIdFiller,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<PubSubFrontend>,
    PubSubFrontend,
    Ethereum,
>;
*/

#[derive(Debug, Clone)]
pub struct ChainClient {
    pub rpc_url: String,
    pub provider: Arc<ChainProvider>,
    pub validator_manager_address: Address,
    // pub chain_gateway_address: Address,
    pub chain_id: u64,
    pub signer: PrivateKeySigner,
    pub chain_gateway_block_deployed: u64,
    pub block_instant_finality: bool,
    pub legacy_gas_estimation: bool,
}

impl ChainClient {
    pub async fn new(
        config: &ChainConfig,
        validator_manager_address: Address,
        // chain_gateway_address: Address,
        signer: PrivateKeySigner,
    ) -> Result<Self> {
        let ws = WsConnect::new(&config.rpc_url);
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet.clone())
            .on_ws(ws.clone())
            .await?;
        let chain_id = provider.get_chain_id().await?;
        let provider = ProviderBuilder::new()
            .with_chain_id(chain_id)
            .filler(GasFiller)
            .filler(NonceFiller::default())
            .wallet(wallet.clone())
            .on_ws(ws.clone())
            .await?;
        let provider: Arc<ChainProvider> = Arc::new(provider);

        // TODO: get the validator_manager_address from chain_gateway itself
        // let chain_gateway = ChainGateway::new(config.chain_gateway_address, provider.clone());
        // let validator_manager_address: Address = chain_gateway.validator_manager().call().await?;

        Ok(ChainClient {
            rpc_url: config.rpc_url.clone(),
            provider,
            validator_manager_address,
            // chain_gateway_address,
            chain_id,
            signer,
            chain_gateway_block_deployed: config.chain_gateway_block_deployed,
            block_instant_finality: config.block_instant_finality.unwrap_or_default(),
            legacy_gas_estimation: config.legacy_gas_estimation.unwrap_or_default(),
        })
    }
}
