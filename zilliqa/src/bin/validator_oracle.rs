use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_rpc_types::{BlockNumberOrTag, Filter};
use anyhow::Result;
use clap::Parser;
use ethers::{
    middleware::MiddlewareBuilder,
    providers::{Middleware, Ws},
    signers::{LocalWallet, Signer},
    types::{TransactionRequest, H160},
};
use futures_util::stream::StreamExt;
use std::{path::PathBuf, str::FromStr};
use zilliqa::{
    contracts,
    crypto::{NodePublicKey, SecretKey},
    state::contract_addr,
    uccb::cfg::ZQ2Config,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
}

impl zilliqa::uccb::Args for Args {
    fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    fn config_file(&self) -> &PathBuf {
        &self.config_file
    }
}

struct ValidatorOracle {
    secret_key: SecretKey,
    zq2_config: ZQ2Config,
}

impl ValidatorOracle {
    pub fn new(secret_key: SecretKey, zq2_config: ZQ2Config) -> Self {
        Self {
            secret_key,
            zq2_config,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let _ = self.get_stakers().await?;
        // println!("Stakers: {}\n", serde_json::to_string(&stakers)?);

        self.listen_to_staker_updates().await
    }

    async fn listen_to_staker_updates(&self) -> Result<()> {
        let filter = Filter::new()
            .address(contract_addr::DEPOSIT)
            // Must be the same signature as the event in deposit.sol
            .event("StakerAdded(bytes)")
            .from_block(BlockNumberOrTag::Latest);

        let ws = WsConnect::new(&self.zq2_config.rpc_url);
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        let subscription = provider.subscribe_logs(&filter).await?;
        let mut stream = subscription.into_stream();
        while let Some(log) = stream.next().await {
            // TODO: update validator manager(s) only if leader
            println!("Subscription log: {log:?}");
        }

        Ok(())
    }

    async fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        let ws = Ws::connect(&self.zq2_config.rpc_url).await?;
        let provider = ethers::providers::Provider::<Ws>::new(ws);
        let chain_id = provider.get_chainid().await?;
        let wallet = LocalWallet::from_str(self.secret_key.to_hex().as_str())?;
        let client = provider
            .with_signer(wallet.clone().with_chain_id(chain_id.as_u64()))
            .nonce_manager(wallet.address());

        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT.into_array()))
            .data(contracts::deposit::GET_STAKERS.encode_input(&[])?);
        let output = client.call(&tx.into(), None).await.unwrap();
        let stakers = contracts::deposit::GET_STAKERS
            .decode_output(&output)
            .unwrap()[0]
            .clone()
            .into_array()
            .unwrap();

        Ok(stakers
            .into_iter()
            .map(|k| NodePublicKey::from_bytes(&k.into_bytes().unwrap()).unwrap())
            .collect())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = zilliqa::uccb::read_config(&args)?;

    let validator_oracle = ValidatorOracle::new(args.secret_key, config.zq2);
    validator_oracle.start().await
}
