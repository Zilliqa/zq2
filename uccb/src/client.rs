use std::sync::Arc;

use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::Address,
    providers::{fillers::*, Identity, Provider, ProviderBuilder, RootProvider, WsConnect},
    pubsub::PubSubFrontend,
    signers::local::PrivateKeySigner,
};
use anyhow::Result;

use crate::cfg::ChainConfig;

pub type ChainProvider = FillProvider<
    JoinFill<
        JoinFill<JoinFill<JoinFill<Identity, ChainIdFiller>, GasFiller>, NonceFiller>,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<PubSubFrontend>,
    PubSubFrontend,
    Ethereum,
>;

#[derive(Debug, Clone)]
pub struct ChainClient {
    pub rpc_url: String,
    pub provider: Arc<ChainProvider>,
    pub validator_manager_address: Address,
    pub chain_id: u64,
    pub signer: PrivateKeySigner,
}

impl ChainClient {
    pub async fn new(
        config: &ChainConfig,
        validator_manager_address: Address,
        signer: PrivateKeySigner,
    ) -> Result<Self> {
        let ws = WsConnect::new(&config.rpc_url);
        let wallet = EthereumWallet::from(signer.clone());

        // Get the chain Id first
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

        Ok(ChainClient {
            rpc_url: config.rpc_url.clone(),
            provider,
            validator_manager_address,
            chain_id,
            signer,
        })
    }
}
