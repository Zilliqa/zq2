pub mod config;
pub mod instance;
pub mod node;

use std::{fmt, str::FromStr};

use anyhow::{anyhow, Error, Result};
use clap::ValueEnum;

#[derive(Clone, Debug, ValueEnum)]
// TODO: decomment when became available
pub enum Chain {
    #[value(name = "zq2-uccbtest")]
    Zq2UccbTest,
    #[value(name = "zq2-infratest")]
    Zq2InfraTest,
    #[value(name = "zq2-perftest")]
    Zq2PerfTest,
    #[value(name = "zq2-devnet")]
    Zq2Devnet,
    #[value(name = "zq2-prototestnet")]
    Zq2ProtoTestnet,
    // #[value(name = "zq2-protomainnet")]
    // Zq2ProtoMainnet,
    // #[value(name = "zq2-testnet")]
    // Zq2Testnet,
    // #[value(name = "zq2-mainnet")]
    // Zq2Mainnet,
}

impl Chain {
    pub fn get_endpoint(&self) -> Option<&'static str> {
        match self {
            Self::Zq2UccbTest => Some("https://api.zq2-uccbtest.zilstg.dev"),
            Self::Zq2InfraTest => Some("https://api.zq2-infratest.zilstg.dev"),
            Self::Zq2PerfTest => Some("https://api.zq2-perftest.zilstg.dev"),
            Self::Zq2Devnet => Some("https://api.zq2-devnet.zilliqa.com"),
            Self::Zq2ProtoTestnet => Some("https://api.zq2-prototestnet.zilliqa.com"),
            // Self::Zq2ProtoMainnet => None,
            // Self::Zq2Testnet => None,
            // Self::Zq2Mainnet => None,
        }
    }

    pub fn get_toml_contents(chain_name: &str) -> Result<&'static str> {
        match chain_name {
            "zq2-uccbtest" => Err(anyhow!("Configuration file for {} not found", chain_name)),
            "zq2-infratest" => Err(anyhow!("Configuration file for {} not found", chain_name)),
            "zq2-perftest" => Ok(include_str!("../resources/chain-specs/zq2-perftest.toml")),
            "zq2-devnet" => Ok(include_str!("../resources/chain-specs/zq2-devnet.toml")),
            "zq2-prototestnet" => Ok(include_str!(
                "../resources/chain-specs/zq2-prototestnet.toml"
            )),
            _ => Err(anyhow!("Configuration file for {} not found", chain_name)),
        }
    }
}

impl FromStr for Chain {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "zq2-uccbtest" => Ok(Self::Zq2UccbTest),
            "zq2-infratest" => Ok(Self::Zq2InfraTest),
            "zq2-perftest" => Ok(Self::Zq2PerfTest),
            "zq2-devnet" => Ok(Self::Zq2Devnet),
            "zq2-prototestnet" => Ok(Self::Zq2ProtoTestnet),
            // "zq2-protomainnet" => Ok(Self::Zq2ProtoMainnet),
            // "zq2-testnet" => Ok(Self::Zq2Testnet),
            // "zq2-mainnet" => Ok(Self::Zq2Mainnet),
            _ => Err(anyhow!("Chain not supported")),
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Zq2UccbTest => write!(f, "zq2-uccbtest"),
            Self::Zq2InfraTest => write!(f, "zq2-infratest"),
            Self::Zq2PerfTest => write!(f, "zq2-perftest"),
            Self::Zq2Devnet => write!(f, "zq2-devnet"),
            Self::Zq2ProtoTestnet => write!(f, "zq2-prototestnet"),
            // Self::Zq2ProtoMainnet => "zq2-protomainnet",
            // Self::Zq2Testnet => "zq2-testnet",
            // Self::Zq2Mainnet => "zq2-mainnet",
        }
    }
}
