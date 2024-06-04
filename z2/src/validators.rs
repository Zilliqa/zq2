use anyhow::{anyhow, Error, Result};
use bitvec::order::verify_for_type;
use regex::Regex;
use reqwest;
use serde::Deserialize;
use serde_json::json;
#[warn(unused_imports)]
/// Implements data structures, enums and functions for vaildators operations.
use toml::Value;

use crate::github;

#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    name: String,
    version: String,
    #[serde(flatten)]
    spec: Value,
}

impl ChainConfig {
    pub async fn new(chain_name: &str) -> Result<Self> {
        let spec = get_chain_spec_config(chain_name).await?;
        let version = github::get_release_or_commit("zq2").await?;

        Ok(ChainConfig {
            name: chain_name.to_string(),
            version,
            spec,
        })
    }

    pub async fn gen_run_script(&self) -> Result<()> {
        todo!();
    }
}

#[derive(Debug)]
enum Chain {
    Devnet,
    ProtoTestnet,
    ProtoMainnet,
    Testnet,
    Mainnet,
}

impl Chain {
    fn as_str(&self) -> &'static str {
        match self {
            Chain::Devnet => "devnet",
            Chain::ProtoTestnet => "prototestnet",
            Chain::ProtoMainnet => "protomainnet",
            Chain::Testnet => "testnet",
            Chain::Mainnet => "mainnet",
        }
    }

    fn get_endpoint(&self) -> Option<&'static str> {
        match self {
            Chain::Devnet => Some("https://api.zq2-devnet.zilliqa.com"),
            Chain::ProtoTestnet => Some("https://api.zq2-prototestnet.zilliqa.com"),
            Chain::ProtoMainnet => None,
            Chain::Testnet => None,
            Chain::Mainnet => None,
        }
    }

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "devnet" => Ok(Chain::Devnet),
            "prototestnet" => Ok(Chain::ProtoTestnet),
            "protomainnet" => Ok(Chain::ProtoMainnet),
            "testnet" => Ok(Chain::Testnet),
            "mainnet" => Ok(Chain::Mainnet),
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