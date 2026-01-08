/// Code to render the validator join configuration and startup script.
use std::env;
use std::path::Path;

use alloy::{
    hex,
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{
        Identity, Provider as _, ProviderBuilder, RootProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
    rpc::types::{TransactionInput, TransactionRequest},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context as _, Result, anyhow};
use ethabi::Token;
use libp2p::PeerId;
use serde::Deserialize;
use tera::Tera;
use tokio::{fs::File, io::AsyncWriteExt};
use toml::Value;
use zilliqa::{
    contracts,
    crypto::{BlsSignature, NodePublicKey},
    state::contract_addr,
};

use crate::{chain::Chain, github, utils};

#[derive(Debug)]
pub struct Validator {
    peer_id: PeerId,
    public_key: NodePublicKey,
    deposit_auth_signature: BlsSignature,
}

impl Validator {
    pub fn new(
        peer_id: PeerId,
        public_key: NodePublicKey,
        deposit_auth_signature: BlsSignature,
    ) -> Result<Self> {
        Ok(Self {
            peer_id,
            public_key,
            deposit_auth_signature,
        })
    }
}

type Wallet = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

#[derive(Debug)]
pub struct SignerClient {
    chain_endpoint: String,
    private_key: String,
}

impl SignerClient {
    pub fn new(chain_endpoint: &str, private_key: &str) -> Result<Self> {
        Ok(Self {
            chain_endpoint: chain_endpoint.to_owned(),
            private_key: private_key.to_owned(),
        })
    }

    pub async fn get_signer(&self) -> Result<Wallet> {
        let key = hex::decode(self.private_key.as_str())?;
        let signer = PrivateKeySigner::from_slice(key.as_slice()).unwrap();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_hyper_http(self.chain_endpoint.parse().unwrap());
        Ok(provider)
    }

    pub async fn deposit(&self, validator: &Validator, params: &DepositParams) -> Result<()> {
        println!(
            "Deposit: adding {} M $ZIL to {}",
            params.amount, validator.peer_id
        );

        let client = self.get_signer().await?;

        // Stake the new validator's funds.
        let data = contracts::deposit_v4::DEPOSIT
            .encode_input(&[
                Token::Bytes(validator.public_key.as_bytes()),
                Token::Bytes(validator.peer_id.to_bytes()),
                Token::Bytes(validator.deposit_auth_signature.to_bytes()),
                Token::Address(params.reward_address.0.0.into()),
                Token::Address(params.signing_address.0.0.into()),
            ])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .value(U256::from(
                params.amount as u128 * 1_000_000u128 * 10u128.pow(18),
            ))
            .input(TransactionInput::both(data.into()));

        // send it!
        let pending_tx = client.send_transaction(tx).await?;

        // get the mined tx
        let receipt = pending_tx.get_receipt().await?;
        let tx = client
            .get_transaction_by_hash(receipt.transaction_hash)
            .await?
            .unwrap();

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn deposit_top_up(&self, bls_public_key: &NodePublicKey, amount: u64) -> Result<()> {
        println!("DepositTopUp: adding {amount} $ZIL stake");

        let client = self.get_signer().await?;

        // Topup the validator's funds.
        let data = contracts::deposit_v4::DEPOSIT_TOPUP
            .encode_input(&[Token::Bytes(bls_public_key.as_bytes())])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .value(U256::from(amount as u128 * 10u128.pow(18)))
            .input(TransactionInput::both(data.into()));

        // send it!
        let pending_tx = client.send_transaction(tx).await?;

        // get the mined tx
        let receipt = pending_tx.get_receipt().await?;
        let tx = client
            .get_transaction_by_hash(receipt.transaction_hash)
            .await?
            .unwrap();

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn unstake(&self, bls_public_key: &NodePublicKey, amount: u64) -> Result<()> {
        println!("Unstake: removing {amount} $ZIL");

        let client = self.get_signer().await?;
        // Unstake the validator's funds.
        let data = contracts::deposit_v4::UNSTAKE
            .encode_input(&[
                Token::Bytes(bls_public_key.as_bytes()),
                Token::Uint((amount as u128 * 10u128.pow(18)).into()),
            ])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .input(TransactionInput::both(data.into()));

        // send it!
        let pending_tx = client.send_transaction(tx).await?;

        // get the mined tx
        let receipt = pending_tx.get_receipt().await?;
        let tx = client
            .get_transaction_by_hash(receipt.transaction_hash)
            .await?
            .unwrap();

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn withdraw(&self, bls_public_key: &NodePublicKey, count: u8) -> Result<()> {
        println!("Withdraw: pulling available unstaked funds from deposit contract");

        let client = self.get_signer().await?;
        // Withdraw the validator's funds.
        let data = contracts::deposit_v4::WITHDRAW
            .encode_input(&[
                Token::Bytes(bls_public_key.as_bytes()),
                Token::Uint((count as u128).into()),
            ])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .input(TransactionInput::both(data.into()));
        // send it!
        let pending_tx = client.send_transaction(tx).await?;

        // get the mined tx
        let receipt = pending_tx.get_receipt().await?;
        let tx = client
            .get_transaction_by_hash(receipt.transaction_hash)
            .await?
            .unwrap();

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn get_stake(&self, public_key: &NodePublicKey) -> Result<u128> {
        let client = self.get_signer().await?;

        let data = contracts::deposit_v4::GET_STAKE
            .encode_input(&[Token::Bytes(public_key.as_bytes())])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .input(TransactionInput::both(data.into()));
        let output = client.call(tx).await.unwrap();

        Ok(contracts::deposit_v4::GET_STAKE
            .decode_output(&output)
            .unwrap()[0]
            .clone()
            .into_uint()
            .unwrap()
            .as_u128())
    }

    pub async fn get_future_stake(&self, public_key: &NodePublicKey) -> Result<u128> {
        let client = self.get_signer().await?;

        let data = contracts::deposit_v8::GET_FUTURE_STAKE
            .encode_input(&[Token::Bytes(public_key.as_bytes())])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .input(TransactionInput::both(data.into()));
        let output = client.call(tx).await.unwrap();

        let future_stake = contracts::deposit_v8::GET_FUTURE_STAKE
            .decode_output(&output)
            .unwrap()[0]
            .clone()
            .into_uint()
            .unwrap()
            .as_u128();

        Ok(future_stake)
    }

    pub async fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        let client = self.get_signer().await?;

        let data = contracts::deposit_v4::GET_STAKERS
            .encode_input(&[])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .input(TransactionInput::both(data.into()));
        let output = client.call(tx).await.unwrap();

        let stakers = contracts::deposit_v4::GET_STAKERS
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

    pub async fn get_reward_address(&self, public_key: &NodePublicKey) -> Result<Address> {
        let client = self.get_signer().await?;

        let data = contracts::deposit_v4::GET_REWARD_ADDRESS
            .encode_input(&[Token::Bytes(public_key.as_bytes())])
            .unwrap();
        let tx = TransactionRequest::default()
            .to(contract_addr::DEPOSIT_PROXY)
            .input(TransactionInput::both(data.into()));
        let output = client.call(tx).await.unwrap();

        Ok(contracts::deposit_v4::GET_REWARD_ADDRESS
            .decode_output(&output)
            .unwrap()[0]
            .clone()
            .into_address()
            .unwrap()
            .0
            .into())
    }
}

#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    name: String,
    version: String,
    spec: Value,
}

impl ChainConfig {
    pub async fn new(chain_name: &Chain, pre_release: bool) -> Result<Self> {
        let spec = get_chain_spec_config(&chain_name.to_string()).await?;
        let version = github::get_release_or_commit("zq2", pre_release).await?;

        Ok(ChainConfig {
            name: chain_name.to_string(),
            version,
            spec,
        })
    }

    pub async fn write(&self) -> Result<()> {
        let mut file_path = env::current_dir()?;
        file_path.push(format!("{}.toml", self.name));
        self.write_to_path(&file_path).await
    }

    pub async fn write_to_path(&self, file_path: &Path) -> Result<()> {
        let mut fh = File::create(file_path).await?;
        fh.write_all(toml::to_string(&self.spec).unwrap().as_bytes())
            .await?;
        println!("💾 Validator config: {}", file_path.to_string_lossy());
        Ok(())
    }

    pub fn get_name(&self) -> String {
        self.name.to_string()
    }
}

#[derive(Debug)]
pub struct DepositParams {
    amount: u8,
    reward_address: Address,
    signing_address: Address,
}

impl DepositParams {
    pub fn new(amount: u8, reward_address: &str, signing_address: &str) -> Result<Self> {
        Ok(Self {
            amount,
            reward_address: Address::from_slice(
                hex_string_to_u8_20(reward_address).unwrap().as_slice(),
            ),
            signing_address: Address::from_slice(
                hex_string_to_u8_20(signing_address).unwrap().as_slice(),
            ),
        })
    }
}

fn hex_string_to_u8_20(hex_str: &str) -> Result<[u8; 20], &'static str> {
    // Convert the hex string to a byte vector
    let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .map_err(|_| "Invalid hex string")?;

    if bytes.len() != 20 {
        return Err("Invalid length after decoding");
    }

    let mut array = [0u8; 20];
    array.copy_from_slice(&bytes);

    Ok(array)
}

pub async fn get_chain_spec_config(chain_name: &str) -> Result<Value> {
    let spec_config = Chain::get_toml_contents(chain_name)?;

    let mut config: Value = toml::from_str(spec_config)
        .map_err(|_| anyhow!("Unable to parse {chain_name} TOML".to_string()))?;

    // append default credit-rates
    let rates_str = include_str!("../resources/rpc_rates.toml");
    let rates: Value = toml::from_str(rates_str)
        .map_err(|_| anyhow!("Unable to parse rpc_rates.toml".to_string()))?;
    for node in config
        .get_mut("nodes")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .iter_mut()
    {
        node.as_table_mut().unwrap().insert(
            "credit_rates".to_string(),
            rates.get("credit_rates").unwrap().clone(),
        );
    }

    Ok(config)
}

pub async fn gen_validator_startup_script(
    config: &mut ChainConfig,
    image_tag: &Option<String>,
    otlp_collector_endpoint: &Option<String>,
) -> Result<()> {
    println!("✌️ Generating the validator startup scripts and configuration");
    println!("📋 Chain specification: {}", config.name);
    println!("👤 Role: Node");

    let mut file_path = env::current_dir()?;
    let mut tera_template: Tera = Default::default();
    let mut context = tera::Context::new();

    tera_template.add_raw_template(
        "start_node",
        include_str!("../resources/start_node.tera.sh"),
    )?;

    context.insert("version", &config.version);
    context.insert("chain_name", &config.name);
    if let Some(v) = image_tag {
        context.insert("image_tag", v)
    }

    if let Some(v) = otlp_collector_endpoint {
        let _ = config.spec.as_table_mut().unwrap().insert(
            String::from("otlp_collector_endpoint"),
            toml::Value::String(v.to_string()),
        );
    }

    let script = tera_template
        .render("start_node", &context)
        .context("Whilst rendering start_node.sh script")?;
    config.write().await?;

    file_path.push("start_node.sh");
    let mut fh = File::create(file_path.clone()).await?;
    fh.write_all(script.as_bytes()).await?;
    utils::make_executable(&file_path)?;

    println!("💾 Startup script: {}", file_path.to_string_lossy());

    Ok(())
}
