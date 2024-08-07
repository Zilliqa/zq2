/// Code to render the validator join configuration and startup script.
use std::env;
use std::{convert::TryFrom, str::FromStr};

use anyhow::{anyhow, Context as _, Error, Result};
use blsful::{vsss_rs::ShareIdentifier, Bls12381G2Impl};
use clap::ValueEnum;
use ethabi::Token;
use ethers::{
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
use zilliqa::{contracts, crypto::NodePublicKey, state::contract_addr};

use crate::github;

#[derive(Debug)]
pub struct Validator {
    peer_id: libp2p::PeerId,
    public_key: zilliqa::crypto::NodePublicKey,
    pop: blsful::ProofOfPossession<Bls12381G2Impl>,
}

impl Validator {
    pub fn new(peer_id: &str, public_key: &str, pop_signature: &str) -> Result<Self> {
        Ok(Self {
            peer_id: PeerId::from_str(peer_id).unwrap(),
            public_key: NodePublicKey::from_bytes(hex::decode(public_key).unwrap().as_slice())
                .unwrap(),
            pop: blsful::ProofOfPossession::<Bls12381G2Impl>::try_from(
                hex::decode(pop_signature).unwrap().as_slice(),
            )?,
        })
    }
}

#[derive(Debug)]
pub struct StakeDeposit {
    validator: Validator,
    amount: u8,
    chain_name: Chain,
    private_key: String,
    reward_address: H160,
}

impl StakeDeposit {
    pub fn new(
        validator: Validator,
        amount: u8,
        chain_name: Chain,
        private_key: &str,
        reward_address: &str,
    ) -> Result<Self> {
        Ok(Self {
            validator,
            amount,
            chain_name,
            private_key: private_key.to_owned(),
            reward_address: H160(hex_string_to_u8_20(reward_address).unwrap()),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    name: String,
    version: String,
    spec: Value,
}

impl ChainConfig {
    pub async fn new(chain_name: &Chain) -> Result<Self> {
        let spec = get_chain_spec_config(chain_name.as_str()).await?;
        let version = github::get_release_or_commit("zq2").await?;

        Ok(ChainConfig {
            name: chain_name.as_str().to_owned(),
            version,
            spec,
        })
    }

    pub async fn write(&self) -> Result<()> {
        let mut file_path = env::current_dir()?;
        file_path.push(format!("{}.toml", self.name));
        let mut fh = File::create(file_path.clone()).await?;
        fh.write_all(toml::to_string(&self.spec).unwrap().as_bytes())
            .await?;
        println!("💾 Validator config: {}", file_path.to_string_lossy());
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, ValueEnum)]
// TODO: decomment when became available
pub enum Chain {
    // Devnet,
    #[value(name = "zq2-prototestnet")]
    Zq2ProtoTestnet,
    // ProtoMainnet,
    // Testnet,
    // Mainnet,
    #[value(name = "zq2-mr-prototestnet")]
    Zq2MrProtoTestnet,
    #[value(name = "zq2-protoinfradevnet")]
    Zq2ProtoInfraDevnet,
}

#[allow(dead_code)]
impl Chain {
    fn as_str(&self) -> &'static str {
        match self {
            // Chain::Devnet => "devnet",
            Chain::Zq2ProtoTestnet => "zq2-prototestnet",
            // Chain::ProtoMainnet => "protomainnet",
            // Chain::Testnet => "testnet",
            // Chain::Mainnet => "mainnet",
            Chain::Zq2MrProtoTestnet => "zq2-mr-prototestnet",
            Chain::Zq2ProtoInfraDevnet => "zq2-protoinfradevnet",
        }
    }

    fn get_endpoint(&self) -> Option<&'static str> {
        match self {
            // Chain::Devnet => Some("https://api.zq2-devnet.zilliqa.com"),
            Chain::Zq2ProtoTestnet => Some("https://api.zq2-prototestnet.zilliqa.com"),
            // Chain::ProtoMainnet => None,
            // Chain::Testnet => None,
            // Chain::Mainnet => None,
            Chain::Zq2MrProtoTestnet => Some("https://api.zq2-mr-prototestnet.zilstg.dev"),
            Chain::Zq2ProtoInfraDevnet => Some("https://api.zq2-protoinfradevnet.zilstg.dev"),
        }
    }

    fn from_str(chain_name: &str) -> Result<Self, Error> {
        match chain_name {
            // "devnet" => Ok(Chain::Devnet),
            "zq2-prototestnet" => Ok(Chain::Zq2ProtoTestnet),
            // "protomainnet" => Ok(Chain::ProtoMainnet),
            // "testnet" => Ok(Chain::Testnet),
            // "mainnet" => Ok(Chain::Mainnet),
            "zq2-mr-prototestnet" => Ok(Chain::Zq2ProtoTestnet),
            "zq2-protoinfradevnet" => Ok(Chain::Zq2ProtoTestnet),
            _ => Err(anyhow!("Chain not supported")),
        }
    }

    pub fn get_toml_contents(chain_name: &str) -> Result<&'static str> {
        match chain_name {
            "zq2-prototestnet" => Ok(include_str!(
                "../resources/chain-specs/zq2-prototestnet.toml"
            )),
            "zq2-mr-prototestnet" => Ok(include_str!(
                "../resources/chain-specs/zq2-mr-prototestnet.toml"
            )),
            "zq2-protoinfradevnet" => Ok(include_str!(
                "../resources/chain-specs/zq2-protoinfradevnet.toml"
            )),
            _ => Err(anyhow!("Configuration file for {} not found", chain_name)),
        }
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
    let contents = Chain::get_toml_contents(chain_name)?;
    let config: Value =
        toml::from_str(contents).map_err(|_| anyhow!("Unable to parse TOML".to_string()))?;
    Ok(config)
}

pub async fn gen_validator_startup_script(config: &ChainConfig) -> Result<()> {
    println!("✌️ Generating the validator startup scripts and configuration");
    println!("📋 Chain specification: {}", config.name);
    println!("👤 Role: External Validator");

    let mut file_path = env::current_dir()?;
    let mut tera_template: Tera = Default::default();
    let mut context = tera::Context::new();

    tera_template.add_raw_template(
        "start_validator",
        include_str!("../resources/start_validator.tera.sh"),
    )?;

    context.insert("version", &config.version);
    context.insert("chain_name", &config.name);

    let script = tera_template
        .render("start_validator", &context)
        .context("Whilst rendering start_validator.sh script")?;
    config.write().await?;

    file_path.push("start_validator.sh");
    let mut fh = File::create(file_path.clone()).await?;
    fh.write_all(script.as_bytes()).await?;

    println!("💾 Startup script: {}", file_path.to_string_lossy());

    Ok(())
}

pub async fn deposit_stake(stake: &StakeDeposit) -> Result<()> {
    println!(
        "Deposit: add {} M $ZIL to {}",
        stake.amount, stake.validator.peer_id
    );

    let network_api = stake.chain_name.get_endpoint().unwrap();
    let provider = Provider::<Http>::try_from(network_api)?;

    let chain_id = provider.get_chainid().await?;

    let wallet: LocalWallet = stake
        .private_key
        .as_str()
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id.as_u64());

    let client = SignerMiddleware::new(provider, wallet);

    // Stake the new validator's funds.
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .value(stake.amount as u128 * 1_000_000u128 * 10u128.pow(18))
        .data(
            contracts::deposit::DEPOSIT
                .encode_input(&[
                    Token::Bytes(stake.validator.public_key.as_bytes()),
                    Token::Bytes(stake.validator.peer_id.to_bytes()),
                    Token::Bytes(stake.validator.pop.0.to_compressed().to_vec()),
                    Token::Address(stake.reward_address),
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
