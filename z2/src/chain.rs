pub mod config;
pub mod instance;
pub mod node;

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use colored::Colorize;
use strum::EnumProperty;
use strum_macros::{Display, EnumString};

#[derive(Clone, Debug, ValueEnum, Display, EnumString, EnumProperty)]
// TODO: decomment when became available
pub enum Chain {
    #[value(name = "zq2-richard")]
    #[strum(
        serialize = "zq2-richard",
        props(
            endpoint = "https://api.zq2-richard.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2Richard,
    #[value(name = "zq2-uccbtest")]
    #[strum(
        serialize = "zq2-uccbtest",
        props(
            endpoint = "https://api.zq2-uccbtest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2UccbTest,
    #[value(name = "zq2-infratest")]
    #[strum(
        serialize = "zq2-infratest",
        props(
            endpoint = "https://api.zq2-infratest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2InfraTest,
    #[value(name = "zq2-perftest")]
    #[strum(
        serialize = "zq2-perftest",
        props(
            endpoint = "https://api.zq2-perftest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2PerfTest,
    #[value(name = "zq2-devnet")]
    #[strum(
        serialize = "zq2-devnet",
        props(
            endpoint = "https://api.zq2-devnet.zilliqa.com",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2Devnet,
    #[value(name = "zq2-prototestnet")]
    #[strum(
        serialize = "zq2-prototestnet",
        props(
            endpoint = "https://api.zq2-prototestnet.zilliqa.com",
            project_id = "prj-d-zq2-testnet-g13pnaa8"
        )
    )]
    Zq2ProtoTestnet,
    #[value(name = "zq2-protomainnet")]
    #[strum(
        serialize = "zq2-protomainnet",
        props(
            endpoint = "https://api.zq2-protomainnet.zilliqa.com",
            project_id = "prj-p-zq2-mainnet-sn5n8wfl"
        )
    )]
    Zq2ProtoMainnet,
    // #[value(name = "zq2-testnet")]
    // #[strum(serialize = "zq2-testnet", props(endpoint = "https://api.zq2-testnet.zilliqa.com", project_id = "prj-d-zq2-testnet-g13pnaa8"))]
    // Zq2Testnet,
    // #[value(name = "zq2-mainnet")]
    // #[strum(serialize = "zq2-mainnet", props(endpoint = "https://api.zq2-mainnet.zilliqa.com", project_id = "prj-p-zq2-mainnet-sn5n8wfl"))]
    // Zq2Mainnet,
}

impl Chain {
    pub fn get_endpoint(&self) -> Result<&'static str> {
        let endpoint = self.get_str("endpoint");

        if let Some(endpoint) = endpoint {
            println!("{}", format!("Using the endpoint {}", endpoint).green());
            return Ok(endpoint);
        }

        Err(anyhow!(
            "{}",
            format!("endpoint not available for the chain {}", self).red()
        ))
    }
    pub fn get_project_id(&self) -> Result<&'static str> {
        let project_id = self.get_str("project_id");

        if let Some(project_id) = project_id {
            println!("{}", format!("Using the project ID {}", project_id).green());
            return Ok(project_id);
        }

        Err(anyhow!(
            "{}",
            format!("project_id not available for the chain {}", self).red()
        ))
    }

    pub fn get_toml_contents(chain_name: &str) -> Result<&'static str> {
        match chain_name {
            "zq2-richard" => Ok(include_str!("../resources/chain-specs/zq2-richard.toml")),
            "zq2-uccbtest" => Ok(include_str!("../resources/chain-specs/zq2-uccbtest.toml")),
            "zq2-infratest" => Err(anyhow!("Configuration file for {} not found", chain_name)),
            "zq2-perftest" => Ok(include_str!("../resources/chain-specs/zq2-perftest.toml")),
            "zq2-devnet" => Ok(include_str!("../resources/chain-specs/zq2-devnet.toml")),
            "zq2-prototestnet" => Ok(include_str!(
                "../resources/chain-specs/zq2-prototestnet.toml"
            )),
            "zq2-protomainnet" => Ok(include_str!(
                "../resources/chain-specs/zq2-protomainnet.toml"
            )),
            _ => Err(anyhow!("Configuration file for {} not found", chain_name)),
        }
    }
}
