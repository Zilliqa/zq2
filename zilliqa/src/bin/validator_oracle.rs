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
use tokio::sync::watch;
use zilliqa::{
    contracts,
    crypto::{NodePublicKey, SecretKey},
    state::contract_addr,
    uccb::{
        cfg::{Config, ZQ2Config},
        client::ChainClient,
    },
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
    wallet: LocalWallet,
    zq2_config: ZQ2Config,
    validators: Vec<NodePublicKey>,
    chain_clients: Vec<ChainClient>,
}

impl ValidatorOracle {
    pub async fn new(secret_key: SecretKey, config: Config) -> Result<Self> {
        let wallet = LocalWallet::from_str(secret_key.to_hex().as_str())?;
        let mut chain_clients = Vec::<ChainClient>::new();
        for chain_config in config.chain_configs {
            chain_clients.push(
                ChainClient::new(
                    &chain_config,
                    H160(**config.zq2.validator_manager_address),
                    wallet.clone(),
                )
                .await?,
            );
        }

        Ok(Self {
            secret_key,
            wallet,
            zq2_config: config.zq2,
            validators: vec![],
            chain_clients,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        self.validators = self.get_stakers().await?;
        // println!("Stakers: {}\n", serde_json::to_string(&stakers)?);

        let (sender, mut receiver) = watch::channel(self.validators.clone());

        self.listen_to_staker_updates(sender).await
    }

    async fn listen_to_staker_updates(
        &self,
        sender: watch::Sender<Vec<NodePublicKey>>,
    ) -> Result<()> {
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
            // TODO: infer if staker added or removed
            println!("Subscription log: {log:?}");

            sender.send(self.validators.clone());
        }

        Ok(())
    }

    async fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        let ws = Ws::connect(&self.zq2_config.rpc_url).await?;
        let provider = ethers::providers::Provider::<Ws>::new(ws);
        let chain_id = provider.get_chainid().await?;
        let client = provider
            .with_signer(self.wallet.clone().with_chain_id(chain_id.as_u64()))
            .nonce_manager(self.wallet.address());

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

    /*
    async fn update_validator_manager(&self, validators: &Vec<NodePublicKey>) -> Result<()> {
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
    */
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = zilliqa::uccb::read_config(&args)?;

    let mut validator_oracle = ValidatorOracle::new(args.secret_key, config).await?;
    validator_oracle.start().await
}
