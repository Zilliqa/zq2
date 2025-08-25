/// Code to render the validator join configuration and startup script.
use std::env;
use std::{convert::TryFrom, path::Path, sync::Arc};

use anyhow::{Context as _, Result, anyhow};
use ethabi::Token;
use ethers::{
    contract::abigen,
    core::types::TransactionRequest,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::H160,
};
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

    pub async fn get_signer(&self) -> Result<SignerMiddleware<Provider<Http>, LocalWallet>> {
        let provider = Provider::<Http>::try_from(self.chain_endpoint.clone())?;

        let wallet: LocalWallet = self
            .private_key
            .as_str()
            .parse::<LocalWallet>()?
            .with_chain_id(provider.get_chainid().await?.as_u64());

        Ok(SignerMiddleware::new(provider, wallet))
    }

    pub async fn deposit(&self, validator: &Validator, params: &DepositParams) -> Result<()> {
        println!(
            "Deposit: adding {} M $ZIL to {}",
            params.amount, validator.peer_id
        );

        let client = self.get_signer().await?;

        // Stake the new validator's funds.
        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
            .value(params.amount as u128 * 1_000_000u128 * 10u128.pow(18))
            .data(
                contracts::deposit_v4::DEPOSIT
                    .encode_input(&[
                        Token::Bytes(validator.public_key.as_bytes()),
                        Token::Bytes(validator.peer_id.to_bytes()),
                        Token::Bytes(validator.deposit_auth_signature.to_bytes()),
                        Token::Address(params.reward_address),
                        Token::Address(params.signing_address),
                    ])
                    .unwrap(),
            );

        // send it!
        let pending_tx = client.send_transaction(tx, None).await?;

        // get the mined tx
        let receipt = pending_tx
            .await?
            .ok_or_else(|| anyhow::anyhow!("tx dropped from mempool"))?;
        let tx = client.get_transaction(receipt.transaction_hash).await?;

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn deposit_top_up(&self, bls_public_key: &NodePublicKey, amount: u8) -> Result<()> {
        println!("DepositTopUp: adding {amount} $ZIL stake");

        let client = self.get_signer().await?;

        // Topup the validator's funds.
        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
            .value(amount as u128 * 10u128.pow(18))
            .data(
                contracts::deposit_v4::DEPOSIT_TOPUP
                    .encode_input(&[Token::Bytes(bls_public_key.as_bytes())])
                    .unwrap(),
            );

        // send it!
        let pending_tx = client.send_transaction(tx, None).await?;

        // get the mined tx
        let receipt = pending_tx
            .await?
            .ok_or_else(|| anyhow::anyhow!("tx dropped from mempool"))?;
        let tx = client.get_transaction(receipt.transaction_hash).await?;

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn unstake(&self, bls_public_key: &NodePublicKey, amount: u8) -> Result<()> {
        println!("Unstake: removing {amount} $ZIL");

        let client = self.get_signer().await?;
        // Unstake the validator's funds.
        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
            .data(
                contracts::deposit_v4::UNSTAKE
                    .encode_input(&[
                        Token::Bytes(bls_public_key.as_bytes()),
                        Token::Uint((amount as u128 * 10u128.pow(18)).into()),
                    ])
                    .unwrap(),
            );

        // send it!
        let pending_tx = client.send_transaction(tx, None).await?;

        // get the mined tx
        let receipt = pending_tx
            .await?
            .ok_or_else(|| anyhow::anyhow!("tx dropped from mempool"))?;
        let tx = client.get_transaction(receipt.transaction_hash).await?;

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn withdraw(&self, bls_public_key: &NodePublicKey, count: u8) -> Result<()> {
        println!("Withdraw: pulling available unstaked funds from deposit contract");

        let client = self.get_signer().await?;
        // Withdraw the validator's funds.
        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
            .data(
                contracts::deposit_v4::UNSTAKE
                    .encode_input(&[
                        Token::Bytes(bls_public_key.as_bytes()),
                        Token::Uint((count as u128).into()),
                    ])
                    .unwrap(),
            );

        // send it!
        let pending_tx = client.send_transaction(tx, None).await?;

        // get the mined tx
        let receipt = pending_tx
            .await?
            .ok_or_else(|| anyhow::anyhow!("tx dropped from mempool"))?;
        let tx = client.get_transaction(receipt.transaction_hash).await?;

        println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
        println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

        Ok(())
    }

    pub async fn get_stake(&self, public_key: &NodePublicKey) -> Result<u128> {
        let client = self.get_signer().await?;

        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
            .data(
                contracts::deposit_v4::GET_STAKE
                    .encode_input(&[Token::Bytes(public_key.as_bytes())])
                    .unwrap(),
            );
        let output = client.call(&tx.into(), None).await.unwrap();

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

        abigen!(
            DEPOSIT_V4,
            r#"[
                function getFutureStake(bytes calldata blsPubKey) public view returns (uint256)
            ]"#,
            derives(serde::Deserialize, serde::Serialize);
        );

        let client = Arc::new(client.provider().to_owned());
        let contract = DEPOSIT_V4::new(H160(contract_addr::DEPOSIT_PROXY.into_array()), client);

        let future_stake = contract
            .get_future_stake(public_key.as_bytes().into())
            .call()
            .await?
            .as_u128();

        Ok(future_stake)
    }

    pub async fn get_stakers(&self) -> Result<Vec<NodePublicKey>> {
        let client = self.get_signer().await?;

        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
            .data(
                contracts::deposit_v4::GET_STAKERS
                    .encode_input(&[])
                    .unwrap(),
            );
        let output = client.call(&tx.into(), None).await.unwrap();

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

    pub async fn get_reward_address(&self, public_key: &NodePublicKey) -> Result<H160> {
        let client = self.get_signer().await?;

        let tx = TransactionRequest::new()
            .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
            .data(
                contracts::deposit_v4::GET_REWARD_ADDRESS
                    .encode_input(&[Token::Bytes(public_key.as_bytes())])
                    .unwrap(),
            );
        let output = client.call(&tx.into(), None).await.unwrap();

        Ok(contracts::deposit_v4::GET_REWARD_ADDRESS
            .decode_output(&output)
            .unwrap()[0]
            .clone()
            .into_address()
            .unwrap())
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
    reward_address: H160,
    signing_address: H160,
}

impl DepositParams {
    pub fn new(amount: u8, reward_address: &str, signing_address: &str) -> Result<Self> {
        Ok(Self {
            amount,
            reward_address: H160(hex_string_to_u8_20(reward_address).unwrap()),
            signing_address: H160(hex_string_to_u8_20(signing_address).unwrap()),
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

    let config: Value =
        toml::from_str(spec_config).map_err(|_| anyhow!("Unable to parse TOML".to_string()))?;
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
