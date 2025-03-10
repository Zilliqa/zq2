pub mod config;
pub mod instance;
pub mod node;

use anyhow::{Result, anyhow};
use clap::ValueEnum;
use colored::Colorize;
use serde_json::{Value, json};
use strum::EnumProperty;
use strum_macros::{Display, EnumString};
use zilliqa::cfg::{ContractUpgradeConfig, ContractUpgrades, ReinitialiseParams};

#[derive(Clone, Debug, ValueEnum, Display, EnumString, EnumProperty, PartialEq)]
// TODO: decomment when became available
pub enum Chain {
    #[value(name = "zq2-richard")]
    #[strum(
        serialize = "zq2-richard",
        props(
            subdomain = "zq2-richard.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd",
            log_level = "zilliqa=trace"
        )
    )]
    Zq2Richard,
    #[value(name = "zq2-uccbtest")]
    #[strum(
        serialize = "zq2-uccbtest",
        props(
            subdomain = "zq2-uccbtest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd",
            log_level = "zilliqa=trace"
        )
    )]
    Zq2UccbTest,
    #[value(name = "zq2-infratest")]
    #[strum(
        serialize = "zq2-infratest",
        props(
            subdomain = "zq2-infratest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd",
            log_level = "zilliqa=info"
        )
    )]
    Zq2InfraTest,
    #[value(name = "zq2-perftest")]
    #[strum(
        serialize = "zq2-perftest",
        props(
            subdomain = "zq2-perftest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd",
            log_level = "zilliqa=trace"
        )
    )]
    Zq2PerfTest,
    #[value(name = "zq2-devnet")]
    #[strum(
        serialize = "zq2-devnet",
        props(
            subdomain = "zq2-devnet.zilliqa.com",
            project_id = "prj-d-zq2-devnet-c83bkpsd",
            log_level = "zilliqa=trace"
        )
    )]
    Zq2Devnet,
    #[value(name = "zq2-prototestnet")]
    #[strum(
        serialize = "zq2-prototestnet",
        props(
            subdomain = "zq2-prototestnet.zilliqa.com",
            project_id = "prj-d-zq2-testnet-g13pnaa8",
            log_level = "zilliqa=trace"
        )
    )]
    Zq2ProtoTestnet,
    #[value(name = "zq2-protomainnet")]
    #[strum(
        serialize = "zq2-protomainnet",
        props(
            subdomain = "zq2-protomainnet.zilliqa.com",
            project_id = "prj-p-zq2-mainnet-sn5n8wfl",
            log_level = "zilliqa=trace"
        )
    )]
    Zq2ProtoMainnet,
    // #[value(name = "zq2-testnet")]
    // #[strum(
    //     serialize = "zq2-testnet",
    //     props(
    //         subdomain = "zq2-testnet.zilliqa.com",
    //         project_id = "prj-d-zq2-testnet-g13pnaa8",
    //         log_level = "zilliqa=trace"
    //     )
    // )]
    // Zq2Testnet,
    // #[value(name = "zq2-mainnet")]
    // #[strum(
    //     serialize = "zq2-mainnet",
    //     props(
    //         subdomain = "zq2-mainnet.zilliqa.com",
    //         project_id = "prj-p-zq2-mainnet-sn5n8wfl",
    //         log_level = "zilliqa=trace"
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
            "zq2-infratest" => Ok(include_str!("../resources/chain-specs/zq2-infratest.toml")),
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

    // Warning: Contract upgrades occur only at epoch boundaries, ie at block heights which are a multiple of blocks_per_epoch
    pub fn get_contract_upgrades_block_heights(&self) -> ContractUpgrades {
        match self {
            Self::Zq2Devnet => ContractUpgrades {
                deposit_v3: None,
                deposit_v4: None,
                deposit_v5: Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: Some(ReinitialiseParams {
                        withdrawal_period: 5 * 60, // 5 minutes
                    }),
                }),
            },
            Self::Zq2ProtoMainnet => ContractUpgrades {
                // estimated: 2024-12-20T23:33:12Z
                deposit_v3: Some(ContractUpgradeConfig::from_height(5342400)),
                // estimated: 2025-02-12T13:25:00Z
                deposit_v4: Some(ContractUpgradeConfig::from_height(7966800)),
                deposit_v5: None,
            },
            Self::Zq2ProtoTestnet => ContractUpgrades {
                deposit_v3: Some(ContractUpgradeConfig::from_height(8406000)),
                // estimated: 2025-02-03T13:55:00Z
                deposit_v4: Some(ContractUpgradeConfig::from_height(10890000)),
                deposit_v5: None,
            },
            _ => ContractUpgrades::default(),
        }
    }

    pub fn genesis_fork(&self) -> Option<Value> {
        match self {
            Chain::Zq2ProtoTestnet | Chain::Zq2ProtoMainnet => Some(json!({
                "at_height": 0,
                "call_mode_1_sets_caller_to_parent_caller": false,
                "failed_scilla_call_from_gas_exempt_caller_causes_revert": false,
                "scilla_messages_can_call_evm_contracts": false,
                "scilla_contract_creation_increments_account_balance": false,
                "scilla_json_preserve_order": false,
                "scilla_call_respects_evm_state_changes": false,
                "only_mutated_accounts_update_state": false,
                "scilla_call_gas_exempt_addrs": [],
                "scilla_block_number_returns_current_block": false,
            })),
            _ => None,
        }
    }

    pub fn get_forks(&self) -> Option<Vec<Value>> {
        match self {
            Chain::Zq2ProtoTestnet => Some(vec![
                json!({
                    "at_height": 7855000,
                    "scilla_call_gas_exempt_addrs": [
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
                }),
                // estimated: 2024-12-18T14:57:53Z
                json!({ "at_height": 8404000, "failed_scilla_call_from_gas_exempt_caller_causes_revert": true, "call_mode_1_sets_caller_to_parent_caller": true }),
                // estimated: 2025-01-15T09:10:37Z
                json!({ "at_height": 10200000, "scilla_messages_can_call_evm_contracts": true }),
                // estimated: 2025-02-12T12:08:37Z
                json!({ "at_height": 11152000, "scilla_contract_creation_increments_account_balance": true, "scilla_json_preserve_order": true }),
                // estimated: 2025-03-07T12:35:25Z
                json!({ "at_height": 12693600, "scilla_call_respects_evm_state_changes": true }),
                // estimated: 2025-03-11T12:58:08Z
                json!({ "at_height": 12884400, "only_mutated_accounts_update_state": true, "scilla_block_number_returns_current_block": true }),
            ]),
            Chain::Zq2ProtoMainnet => Some(vec![
                json!({
                    "at_height": 4683779,
                    "scilla_call_gas_exempt_addrs": [
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
                }),
                // estimated: 2024-12-20T23:33:12Z
                json!({ "at_height": 5342400, "failed_scilla_call_from_gas_exempt_caller_causes_revert": true, "call_mode_1_sets_caller_to_parent_caller": true }),
                json!({ "at_height": 7685881, "scilla_json_preserve_order": true }),
                // estimated: 2025-02-12T13:25:00Z
                json!({ "at_height": 7966800, "scilla_messages_can_call_evm_contracts": true, "scilla_contract_creation_increments_account_balance": true }),
            ]),
            _ => None,
        }
    }

    pub fn get_subdomain(&self) -> Result<&'static str> {
        let endpoint = self.get_str("subdomain");

        if let Some(endpoint) = endpoint {
            return Ok(endpoint);
        }

        Err(anyhow!(
            "{}",
            format!("Subdomain not available for the chain {}", self).red()
        ))
    }

    pub fn get_api_endpoint(&self) -> Result<String> {
        Ok(format!("https://api.{}", self.get_subdomain()?))
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

    pub fn get_log_level(&self) -> Result<&'static str> {
        let log_level = self.get_str("log_level");

        Ok(log_level.unwrap_or("zilliqa=trace"))
    }
}
