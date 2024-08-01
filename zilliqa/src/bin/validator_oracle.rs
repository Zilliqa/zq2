use alloy::{
    consensus::{SignableTransaction, TxEnvelope},
    contract::{ContractInstance, DynCallBuilder, Interface, SolCallBuilder},
    dyn_abi::{parser::utils::char_parser, DynSolValue},
    eips::BlockNumberOrTag,
    json_abi::JsonAbi,
    network::{
        eip2718::Encodable2718, EthereumWallet, NetworkWallet, TransactionBuilder, TxSigner,
    },
    primitives::{Bytes, TxKind},
    providers::{Provider, ProviderBuilder, WsConnect},
    pubsub::PubSubFrontend,
    rpc::types::{
        eth::{TransactionInput, TransactionRequest},
        Filter,
    },
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use clap::Parser;
use futures_util::stream::StreamExt;
use std::{path::PathBuf, str::FromStr};
use tokio::sync::watch;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;
use zilliqa::{
    contracts,
    crypto::{NodePublicKey, SecretKey},
    state::contract_addr,
    uccb::{
        cfg::{ChainConfig, Config, ZQ2Config},
        client::ChainClient,
    },
};

const VALIDATOR_MANAGER_ABI_JSON: &str =
    include_str!["../contracts/uccb/out/ValidatorManager.sol/ValidatorManager.json"];

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
    signer: PrivateKeySigner,
    zq2_config: ZQ2Config,
    chain_clients: Vec<ChainClient>,
    deploy_abi: JsonAbi,
    validator_manager_abi: JsonAbi,
}

impl ValidatorOracle {
    pub async fn new(secret_key: SecretKey, config: Config) -> Result<Self> {
        let signer = PrivateKeySigner::from_str(secret_key.to_hex().as_str())?;
        let mut chain_clients = vec![Self::create_zq2_chain_client(config.clone(), &signer).await?];

        for chain_config in config.chain_configs {
            chain_clients.push(
                ChainClient::new(
                    &chain_config,
                    config.zq2.validator_manager_address,
                    signer.clone(),
                )
                .await?,
            );
        }

        let validator_manager_abi = serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(VALIDATOR_MANAGER_ABI_JSON)?["abi"].clone(),
        )?;
        Ok(Self {
            signer,
            zq2_config: config.zq2,
            chain_clients,
            deploy_abi: serde_json::from_value(serde_json::to_value(
                contracts::deposit::ABI.clone(),
            )?)?,
            validator_manager_abi,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        /*
        info!(
            "Starting validator oracle with signer address {}",
            self.signer.address()
        );
        */

        let validators = self.get_stakers().await?;
        info!("Current validator set is: {validators:?}");

        let (sender, receiver) = watch::channel(validators);

        let mut handles = vec![];
        for chain_client in &self.chain_clients {
            let mut receiver = receiver.clone();
            let chain_client = chain_client.clone();
            let validator_manager_abi = self.validator_manager_abi.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let validators = receiver.borrow_and_update().clone();
                    if Self::update_validator_manager(
                        &chain_client,
                        &validators,
                        validator_manager_abi.clone(),
                    )
                    .await
                    .is_err()
                    {
                        error!(
                            "Failed updating the validator manager on {}",
                            chain_client.rpc_url
                        );
                    }

                    if receiver.changed().await.is_err() {
                        break;
                    }
                }
            });
            handles.push(handle);
        }

        let result = self.listen_to_staker_updates(sender).await;

        for handle in handles {
            handle.await?;
        }

        result
    }

    async fn listen_to_staker_updates(
        &mut self,
        sender: watch::Sender<Vec<NodePublicKey>>,
    ) -> Result<()> {
        let filter = Filter::new()
            .address(contract_addr::DEPOSIT)
            // Must be the same signature as the event in deposit.sol
            .event("StakerAdded(bytes)")
            .from_block(BlockNumberOrTag::Finalized);

        let ws = WsConnect::new(&self.zq2_config.rpc_url);
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        let subscription = provider.subscribe_logs(&filter).await?;
        let mut stream = subscription.into_stream();
        while let Some(log) = stream.next().await {
            // TODO: infer if staker added or removed
            info!("Received validator update: {log:?}");

            let validators = self.get_stakers().await?;
            info!("Updating chains to the current validator set to: {validators:?}");

            sender.send(validators)?;
        }

        Ok(())
    }

    async fn create_zq2_chain_client(
        config: Config,
        signer: &PrivateKeySigner,
    ) -> Result<ChainClient> {
        ChainClient::new(
            &ChainConfig {
                rpc_url: config.zq2.rpc_url,
                chain_gateway_address: config.zq2.chain_gateway_address,
                chain_gateway_block_deployed: 0,
                block_instant_finality: None,
                legacy_gas_estimation: None,
            },
            config.zq2.validator_manager_address,
            signer.clone(),
        )
        .await
    }

    fn zq2_chain_client(&self) -> &ChainClient {
        &self.chain_clients[0]
    }

    async fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        debug!("Retreiving validators from the deposit contract");

        let contract: ContractInstance<PubSubFrontend, _> = ContractInstance::new(
            contract_addr::DEPOSIT,
            self.zq2_chain_client().provider.as_ref(),
            Interface::new(self.deploy_abi.clone()),
        );

        let call_builder: DynCallBuilder<_, _, _> = contract.function("getStakers", &vec![])?;
        let output = call_builder.call().await?;
        let validators = if output.len() == 1 {
            output[0]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| NodePublicKey::from_bytes(&k.as_bytes().unwrap()).unwrap())
                .collect()
        } else {
            vec![]
        };

        Ok(validators)
    }

    async fn update_validator_manager(
        chain_client: &ChainClient,
        validators: &[NodePublicKey],
        validator_manager_abi: JsonAbi,
    ) -> Result<()> {
        let validator_manager_interface = Interface::new(validator_manager_abi);

        let contract: ContractInstance<PubSubFrontend, _> = ContractInstance::new(
            chain_client.validator_manager_address,
            chain_client.provider.as_ref(),
            validator_manager_interface.clone(),
        );

        let validators = DynSolValue::Array(
            validators
                .iter()
                .map(|validator| DynSolValue::Address(validator.into_addr()))
                .collect(),
        );

        let call_builder: DynCallBuilder<_, _, _> =
            contract.function("setValidators", &[validators])?.gas_price(1476190480000);

        let output = call_builder.send().await?;
        let receipt = output.get_receipt().await?;
        info!("Receipt from {}: {receipt:?}", &chain_client.rpc_url);

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = zilliqa::uccb::read_config(&args)?;

    let builder = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_line_number(true);
    builder.init();

    let mut validator_oracle = ValidatorOracle::new(args.secret_key, config).await?;
    validator_oracle.start().await
}
