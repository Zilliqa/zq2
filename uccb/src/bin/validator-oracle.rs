use std::{path::PathBuf, str::FromStr};

use alloy::{
    contract::{ContractInstance, DynCallBuilder, Interface},
    dyn_abi::DynSolValue,
    eips::{eip2930::AccessList, BlockNumberOrTag},
    json_abi::JsonAbi,
    network::Ethereum,
    primitives::{Address, FixedBytes},
    providers::Provider,
    pubsub::PubSubFrontend,
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use clap::Parser;
use futures_util::stream::StreamExt;
use tokio::sync::watch;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;
use uccb::{
    cfg::{ChainConfig, Config},
    client::ChainClient,
};
use zilliqa::{contracts, crypto::SecretKey, state::contract_addr};

const VALIDATOR_MANAGER_ABI_JSON: &str =
    include_str!("../../contracts/out/ValidatorManager.sol/ValidatorManager.json");

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
}

struct ValidatorOracle {
    signer: PrivateKeySigner,
    chain_clients: Vec<ChainClient>,
    validator_manager_abi: JsonAbi,
    deposit_contract: ContractInstance<PubSubFrontend, uccb::client::ChainProvider, Ethereum>,
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

        let deploy_abi: JsonAbi =
            serde_json::from_value(serde_json::to_value(contracts::deposit::ABI.clone())?)?;
        let deposit_contract: ContractInstance<PubSubFrontend, _> = ContractInstance::new(
            contract_addr::DEPOSIT,
            chain_clients[0].provider.as_ref().clone(),
            Interface::new(deploy_abi.clone()),
        );

        Ok(Self {
            signer,
            chain_clients,
            validator_manager_abi: serde_json::from_value(
                serde_json::from_str::<serde_json::Value>(VALIDATOR_MANAGER_ABI_JSON)?["abi"]
                    .clone(),
            )?,
            deposit_contract,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting validator oracle with signer address {}",
            self.signer.address()
        );

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
                    if let Err(e) = Self::update_validator_manager(
                        &chain_client,
                        &validators,
                        validator_manager_abi.clone(),
                    )
                    .await
                    {
                        error!(
                            "Failed updating the validator manager on {}: {e}",
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
        sender: watch::Sender<Vec<Address>>,
    ) -> Result<()> {
        let signatures: Vec<FixedBytes<32>> = vec![
            contracts::deposit::STAKER_ADDED_EVT.signature(),
            contracts::deposit::STAKER_REMOVED_EVT.signature(),
        ]
        .into_iter()
        .map(|x| FixedBytes::<32>::from(x.as_fixed_bytes()))
        .collect();

        let filter = Filter::new()
            .address(contract_addr::DEPOSIT)
            .event_signature(signatures)
            .from_block(BlockNumberOrTag::Finalized);

        let subscription = self
            .zq2_chain_client()
            .provider
            .subscribe_logs(&filter)
            .await?;
        let mut stream = subscription.into_stream();
        while let Some(log) = stream.next().await {
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
            },
            config.zq2.validator_manager_address,
            signer.clone(),
        )
        .await
    }

    fn zq2_chain_client(&self) -> &ChainClient {
        &self.chain_clients[0]
    }

    async fn get_stakers(&self) -> Result<Vec<Address>> {
        debug!("Retreiving validators from the deposit contract");

        let call_builder: DynCallBuilder<_, _, _> = self
            .deposit_contract
            .function("getStakerSignerAddresses", &[])?;
        let output = call_builder.call().await?;
        let validators = output[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_address().unwrap())
            .collect();

        Ok(validators)
    }

    async fn update_validator_manager(
        chain_client: &ChainClient,
        validators: &[Address],
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
                .map(|validator| DynSolValue::Address(*validator))
                .collect(),
        );

        let call_builder: DynCallBuilder<_, _, _> = contract
            .function("setValidators", &[validators])?
            // FIXME: this is a workaround for using legacy transaction rather than
            //        EIP-1559 ones; without this Alloy will invoke eth_feeHistory
            //        which zq2 doesn't support currently.
            .access_list(AccessList::default());

        let output = call_builder.send().await?;
        let receipt = output.get_receipt().await?;
        info!("Receipt from {}: {receipt:?}", &chain_client.rpc_url);

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = uccb::read_config(&args.config_file)?;

    let builder = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_line_number(true);
    builder.init();

    let mut validator_oracle = ValidatorOracle::new(args.secret_key, config).await?;
    validator_oracle.start().await
}
