/// Code to render the validator join configuration and startup script.
use std::env;

use crate::github;
use anyhow::{anyhow, Context as _, Error, Result};
use clap::ValueEnum;
use serde::Deserialize;
use tera::Tera;
use tokio::{fs::File, io::AsyncWriteExt};
use toml::Value;

#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    name: String,
    version: String,
    spec: Value,
}

impl ChainConfig {
    pub async fn new(chain_name: &Chain) -> Result<Self> {
        let spec = get_chain_spec_config(&chain_name.as_str().to_owned()).await?;
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
/// To-do: decomment when became available
pub enum Chain {
    // Devnet,
    #[value(name = "prototestnet")]
    ProtoTestnet,
    // ProtoMainnet,
    // Testnet,
    // Mainnet,
}

#[allow(dead_code)]
impl Chain {
    fn as_str(&self) -> &'static str {
        match self {
            // Chain::Devnet => "devnet",
            Chain::ProtoTestnet => "prototestnet",
            // Chain::ProtoMainnet => "protomainnet",
            // Chain::Testnet => "testnet",
            // Chain::Mainnet => "mainnet",
        }
    }

    fn get_endpoint(&self) -> Option<&'static str> {
        match self {
            // Chain::Devnet => Some("https://api.zq2-devnet.zilliqa.com"),
            Chain::ProtoTestnet => Some("https://api.zq2-prototestnet.zilliqa.com"),
            // Chain::ProtoMainnet => None,
            // Chain::Testnet => None,
            // Chain::Mainnet => None,
        }
    }

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            // "devnet" => Ok(Chain::Devnet),
            "prototestnet" => Ok(Chain::ProtoTestnet),
            // "protomainnet" => Ok(Chain::ProtoMainnet),
            // "testnet" => Ok(Chain::Testnet),
            // "mainnet" => Ok(Chain::Mainnet),
            _ => Err(anyhow!("Chain not supported")),
        }
    }
}

fn get_toml_contents(chain_name: &str) -> Result<&'static str> {
    match chain_name {
        "prototestnet" => Ok(include_str!("../resources/chain-specs/prototestnet.toml")),
        _ => Err(anyhow!("Configuration file for {} not found", chain_name)),
    }
}

async fn get_chain_spec_config(chain_name: &str) -> Result<Value> {
    let contents = get_toml_contents(chain_name)?;
    let config: Value =
        toml::from_str(&contents).map_err(|_| anyhow!("Unable to parse TOML".to_string()))?;
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
