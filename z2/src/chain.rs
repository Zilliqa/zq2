pub mod config;
pub mod instance;
pub mod node;

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use colored::Colorize;
use serde_json::{json, Value};
use strum::EnumProperty;
use strum_macros::{Display, EnumString};
use zilliqa::cfg::ContractUpgradesBlockHeights;

#[derive(Clone, Debug, ValueEnum, Display, EnumString, EnumProperty)]
// TODO: decomment when became available
pub enum Chain {
    #[value(name = "zq2-richard")]
    #[strum(
        serialize = "zq2-richard",
        props(
            bootstrap_endpoint = "bootstrap.zq2-richard.zilstg.dev",
            api_endpoint = "https://api.zq2-richard.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2Richard,
    #[value(name = "zq2-uccbtest")]
    #[strum(
        serialize = "zq2-uccbtest",
        props(
            bootstrap_endpoint = "bootstrap.zq2-uccbtest.zilstg.dev",
            api_endpoint = "https://api.zq2-uccbtest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2UccbTest,
    #[value(name = "zq2-infratest")]
    #[strum(
        serialize = "zq2-infratest",
        props(
            bootstrap_endpoint = "bootstrap.zq2-infratest.zilstg.dev",
            api_endpoint = "https://api.zq2-infratest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2InfraTest,
    #[value(name = "zq2-perftest")]
    #[strum(
        serialize = "zq2-perftest",
        props(
            bootstrap_endpoint = "bootstrap.zq2-perftest.zilstg.dev",
            api_endpoint = "https://api.zq2-perftest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2PerfTest,
    #[value(name = "zq2-devnet")]
    #[strum(
        serialize = "zq2-devnet",
        props(
            bootstrap_endpoint = "bootstrap.zq2-devnet.zilliqa.com",
            api_endpoint = "https://api.zq2-devnet.zilliqa.com",
            project_id = "prj-d-zq2-devnet-c83bkpsd"
        )
    )]
    Zq2Devnet,
    #[value(name = "zq2-prototestnet")]
    #[strum(
        serialize = "zq2-prototestnet",
        props(
            bootstrap_endpoint = "bootstrap.zq2-prototestnet.zilliqa.com",
            api_endpoint = "https://api.zq2-prototestnet.zilliqa.com",
            project_id = "prj-d-zq2-testnet-g13pnaa8"
        )
    )]
    Zq2ProtoTestnet,
    #[value(name = "zq2-protomainnet")]
    #[strum(
        serialize = "zq2-protomainnet",
        props(
            bootstrap_endpoint = "bootstrap.zq2-protomainnet.zilliqa.com",
            api_endpoint = "https://api.zq2-protomainnet.zilliqa.com",
            project_id = "prj-p-zq2-mainnet-sn5n8wfl"
        )
    )]
    Zq2ProtoMainnet,
    // #[value(name = "zq2-testnet")]
    // #[strum(
    //     serialize = "zq2-testnet",
    //     props(
    //         bootstrap_endpoint = "bootstrap.zq2-testnet.zilliqa.com",
    //         api_endpoint = "https://api.zq2-testnet.zilliqa.com",
    //         project_id = "prj-d-zq2-testnet-g13pnaa8"
    //     )
    // )]
    // Zq2Testnet,
    // #[value(name = "zq2-mainnet")]
    // #[strum(
    //     serialize = "zq2-mainnet",
    //     props(
    //         bootstrap_endpoint = "bootstrap.zq2-mainnet.zilliqa.com",
    //         api_endpoint = "https://api.zq2-mainnet.zilliqa.com",
    //         project_id = "prj-p-zq2-mainnet-sn5n8wfl"
    //     )
    // )]
    // Zq2Mainnet,
}

impl Chain {
    pub fn get_toml_contents(chain_name: &str) -> Result<&'static str> {
        match chain_name {
            "zq2-richard" => Ok(include_str!("../resources/chain-specs/zq2-richard.toml")),
            "zq2-uccbtest" => Ok(include_str!("../resources/chain-specs/zq2-uccbtest.toml")),
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

    pub fn get_whitelisted_evm_contracts(&self) -> Vec<&'static str> {
        match self {
            Self::Zq2ProtoMainnet => vec![
                "0x95347b860Bd49818AFAccCA8403C55C23e7BB9ED",
                "0xe64cA52EF34FdD7e20C0c7fb2E392cc9b4F6D049",
                "0x63B991C17010C21250a0eA58C6697F696a48cdf3",
                "0x241c677D9969419800402521ae87C411897A029f",
                "0x2274005778063684fbB1BfA96a2b725dC37D75f9",
                "0x598FbD8B68a8B7e75b8B7182c750164f348907Bc",
                "0x2938fF251Aecc1dfa768D7d0276eB6d073690317",
                "0x17D5af5658A24bd964984b36d28e879a8626adC3",
                "0xCcF3Ea256d42Aeef0EE0e39Bfc94bAa9Fa14b0Ba",
                "0xc6F3dede529Af9D98a11C5B32DbF03Bf34272ED5",
                "0x7D2fF48c6b59229d448473D267a714d29F078D3E",
                "0xE9D47623bb2B3C497668B34fcf61E101a7ea4058",
                "0x03A79429acc808e4261a68b0117aCD43Cb0FdBfa",
                "0x097C26F8A93009fd9d98561384b5014D64ae17C2",
                "0x01035e423c40a9ad4F6be2E6cC014EB5617c8Bd6",
                "0x9C3fE3f471d8380297e4fB222eFb313Ee94DFa0f",
                "0x20Dd5D5B5d4C72676514A0eA1052d0200003d69D",
                "0xbfDe2156aF75a29d36614bC1F8005DD816Bd9200",
            ],
            Self::Zq2ProtoTestnet => vec![
                "0x60E6b5b1B8D3E373E1C04dC0b4f5624776bcBB60",
                "0x7013Da2653453299Efb867EfcCCcB1A6d5FE1384",
                "0x8618d39a8276D931603c6Bc7306af6A53aD2F1F3",
                "0xE90Dd366D627aCc5feBEC126211191901A69f8a0",
                "0x5900Ac075A67742f5eA4204650FEad9E674c664F",
                "0x28e8d39fc68eaa27c88797eb7d324b4b97d5b844",
                "0x51b9f3ddb948bcc16b89b48d83b920bc01dbed55",
                "0x1fD09F6701a1852132A649fe9D07F2A3b991eCfA",
                "0x878c5008A348A60a5B239844436A7b483fAdb7F2",
                "0x8895Aa1bEaC254E559A3F91e579CF4a67B70ce02",
                "0x453b11386FBd54bC532892c0217BBc316fc7b918",
                "0xaD581eC62eA08831c8FE2Cd7A1113473fE40A057",
            ],
            _ => vec![],
        }
    }

    // Warning: Contract upgrades occur only at epoch boundaries, ie at block heights which are a multiple of blocks_per_epoch
    pub fn get_contract_upgrades_block_heights(&self) -> ContractUpgradesBlockHeights {
        match self {
            Self::Zq2Devnet => ContractUpgradesBlockHeights {
                deposit_v3: Some(3600),
            },
            Self::Zq2ProtoMainnet => ContractUpgradesBlockHeights {
                // estimated: 2024-12-20T23:33:12Z
                deposit_v3: Some(5342400),
            },
            Self::Zq2ProtoTestnet => ContractUpgradesBlockHeights {
                deposit_v3: Some(8406000),
            },
            _ => ContractUpgradesBlockHeights::default(),
        }
    }

    pub fn get_forks(&self) -> Option<Vec<Value>> {
        match self {
            Chain::Zq2ProtoTestnet => Some(vec![
                json!({ "at_height": 0, "failed_scilla_call_from_gas_exempt_caller_causes_revert": false, "call_mode_1_sets_caller_to_parent_caller": false }),
                // estimated: 2024-12-18T14:57:53Z
                json!({ "at_height": 8404000, "failed_scilla_call_from_gas_exempt_caller_causes_revert": true, "call_mode_1_sets_caller_to_parent_caller": true }),
            ]),
            Chain::Zq2ProtoMainnet => Some(vec![
                json!({ "at_height": 0, "failed_scilla_call_from_gas_exempt_caller_causes_revert": false, "call_mode_1_sets_caller_to_parent_caller": false }),
                // estimated: 2024-12-20T23:33:12Z
                json!({ "at_height": 5342400, "failed_scilla_call_from_gas_exempt_caller_causes_revert": true, "call_mode_1_sets_caller_to_parent_caller": true }),
            ]),
            _ => None,
        }
    }

    pub fn get_bootstrap_endpoint(&self) -> Result<&'static str> {
        let endpoint = self.get_str("bootstrap_endpoint");

        if let Some(endpoint) = endpoint {
            println!(
                "{}",
                format!("Using the bootstrap endpoint {}", endpoint).green()
            );
            return Ok(endpoint);
        }

        Err(anyhow!(
            "{}",
            format!("bootstrap endpoint not available for the chain {}", self).red()
        ))
    }

    pub fn get_api_endpoint(&self) -> Result<&'static str> {
        let endpoint = self.get_str("api_endpoint");

        if let Some(endpoint) = endpoint {
            println!("{}", format!("Using the API endpoint {}", endpoint).green());
            return Ok(endpoint);
        }

        Err(anyhow!(
            "{}",
            format!("API endpoint not available for the chain {}", self).red()
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
}
