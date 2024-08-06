use std::{collections::BTreeMap, path::PathBuf, str::FromStr};

use alloy::{
    contract::{ContractInstance, DynCallBuilder, Interface},
    dyn_abi::DynSolValue,
    eips::{eip2930::AccessList, BlockNumberOrTag},
    json_abi::JsonAbi,
    network::Ethereum,
    primitives::{Address, FixedBytes},
    providers::Provider,
    pubsub::PubSubFrontend,
    rpc::types::{
        eth::{TransactionInput, TransactionRequest},
        Filter,
    },
    signers::local::PrivateKeySigner,
    signers::{Signer, SignerSync},
    sol_types::{sol, SolCall},
};
use anyhow::Result;
use clap::Parser;
use futures_util::stream::StreamExt;
use tokio::{select, sync::watch};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;
use zilliqa::{
    contracts,
    crypto::{NodePublicKey, SecretKey},
    state::contract_addr,
    uccb::{cfg::Config, client::ChainClient},
};

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
    pending_validators: BTreeMap<u64, Vec<Address>>,
}

impl ValidatorOracle {
    pub async fn new(secret_key: SecretKey, config: Config) -> Result<Self> {
        let signer = PrivateKeySigner::from_str(secret_key.to_hex().as_str())?;

        // We need to convert ethabi::Contract -> alloy::json_abi::JsonAbi. Both JSON
        // representations are the same.
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
            // See above comment regarding ethabi::Contract -> alloy::json_abi::JsonAbi.
            validator_manager_abi: serde_json::from_value(
                serde_json::from_str::<serde_json::Value>(VALIDATOR_MANAGER_ABI_JSON)?["contracts"]
                    ["contracts/src/ValidatorManager.sol"]["ValidatorManager"]["abi"]
                    .clone(),
            )?,
            deposit_contract,
            pending_validators: BTreeMap::new(),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting validator oracle with signer address {}",
            self.signer.address()
        );

        let validators = self.get_stakers().await?;
        info!("Current validator set is: {}", Display(&validators));

        let (sender, receiver) = watch::channel(validators);

        let mut handles = vec![];
        for chain_client in &self.chain_clients {
            let mut receiver = receiver.clone();
            let chain_client = chain_client.clone();
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

        let stakers_filter = Filter::new()
            .address(contract_addr::DEPOSIT)
            .event_signature(signatures)
            .to_block(BlockNumberOrTag::Finalized);

        let stakers_subscription = self
            .zq2_chain_client()
            .provider
            .subscribe_logs(&stakers_filter)
            .await?;
        let mut stakers_stream = stakers_subscription.into_stream();

        let new_heads_subscription = self.zq2_chain_client().provider.subscribe_blocks().await?;
        let mut new_heads_stream = new_heads_subscription.into_stream();

        loop {
            select! {
                Some(block) = new_heads_stream.next() => {
                    debug!("Received new head update: {block:?}");

                    let block_numbers: Vec<u64> = self.pending_validators.range(..block.header.number).map(|(&block_number, _)| block_number).collect();
                    if let Some(block_number) = block_numbers.last() {
                        let validators = self.pending_validators.get_mut(block_number).unwrap();
                        info!("Scheduling validator update for block {block_number}: {validators:?}");
                        sender.send(std::mem::take(validators))?;
                    }

                    for block_number in block_numbers {
                        self.pending_validators.remove(&block_number);
                    }
                }
                Some(log) = stakers_stream.next() => {
                    if log.removed {
                        continue;
                    }

                    info!("Validator update event: {log:?}");

                    if let Some(log_block_number) = log.block_number {
                        self.pending_validators.insert(log_block_number, self.get_stakers().await?);
                    }
                }
            }
        }
    }

    fn zq2_chain_client(&self) -> &ChainClient {
        &self.chain_clients[0]
    }

    async fn get_stakers(&self) -> Result<Vec<Address>> {
        debug!("Retreiving validators from the deposit contract");

        let call_builder: DynCallBuilder<_, _, _> =
            self.deposit_contract.function("getStakerData", &[])?;
        let output = call_builder.call().await?;
        let validators = if output.len() == 1 {
            output[0]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_address().unwrap() /*NodePublicKey::from_bytes(k.as_bytes().unwrap()).unwrap()*/)
                .collect()
        } else {
            vec![]
        };

        Ok(validators)
    }

    async fn update_validator_manager(
        chain_client: &ChainClient,
        validators: &[Address],
    ) -> Result<()> {
        info!("Updating validators at {}", &chain_client.rpc_url);

        let contract: ContractInstance<PubSubFrontend, _> =
            zilliqa::uccb::contracts::validator_manager::instance(
                chain_client.validator_manager_address,
                chain_client.provider.as_ref(),
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
