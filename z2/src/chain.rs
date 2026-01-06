pub mod config;
pub mod instance;
pub mod node;

use std::time::Duration;

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
    #[value(name = "zq2-infratest")]
    #[strum(
        serialize = "zq2-infratest",
        props(
            genesis_amount = "900_000_000_000_000_000_000_000_000",
            genesis_deposits_amount = "20_000_000_000_000_000_000_000_000",
            subdomain = "zq2-infratest.zilstg.dev",
            project_id = "prj-d-zq2-devnet-c83bkpsd",
            log_level = "zilliqa=info",
            enable_kms = "false"
        )
    )]
    Zq2InfraTest,
    #[value(name = "zq2-devnet")]
    #[strum(
        serialize = "zq2-devnet",
        props(
            genesis_amount = "900_000_000_000_000_000_000_000_000",
            genesis_deposits_amount = "20_000_000_000_000_000_000_000_000",
            subdomain = "zq2-devnet.zilliqa.com",
            project_id = "prj-d-zq2-devnet-c83bkpsd",
            log_level = "zilliqa=info",
            enable_kms = "false"
        )
    )]
    Zq2Devnet,
    #[value(name = "zq2-testnet")]
    #[strum(
        serialize = "zq2-testnet",
        props(
            genesis_amount = "900_000_000_000_000_000_000_000_000",
            genesis_deposits_amount = "20_000_000_000_000_000_000_000_000",
            subdomain = "zq2-testnet.zilliqa.com",
            project_id = "prj-d-zq2-testnet-g13pnaa8",
            log_level = "zilliqa=info",
            enable_kms = "true"
        )
    )]
    Zq2Testnet,
    #[value(name = "zq2-mainnet")]
    #[strum(
        serialize = "zq2-mainnet",
        props(
            genesis_amount = "100_000_000_000_000_000_000",
            genesis_deposits_amount = "80_000_000_000_000_000_000_000_000",
            validator_control_address = "0xf865745c75E585718c8f115A9317E7Fc8e1195f3",
            subdomain = "zq2-mainnet.zilliqa.com",
            project_id = "prj-p-zq2-mainnet-sn5n8wfl",
            log_level = "zilliqa=info",
            enable_kms = "true"
        )
    )]
    Zq2Mainnet,
}

impl Chain {
    pub fn get_toml_contents(chain_name: &str) -> Result<&'static str> {
        match chain_name {
            "zq2-infratest" => Ok(include_str!("../resources/chain-specs/zq2-infratest.toml")),
            "zq2-devnet" => Ok(include_str!("../resources/chain-specs/zq2-devnet.toml")),
            "zq2-testnet" => Ok(include_str!("../resources/chain-specs/zq2-testnet.toml")),
            "zq2-mainnet" => Ok(include_str!("../resources/chain-specs/zq2-mainnet.toml")),
            _ => Err(anyhow!("Configuration file for {chain_name} not found")),
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
                deposit_v6: Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: None,
                }),
                deposit_v7: Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: None,
                }),
            },
            Self::Zq2Testnet => ContractUpgrades {
                deposit_v3: None,
                deposit_v4: None,
                deposit_v5: Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
                deposit_v6: Some(ContractUpgradeConfig {
                    height: 14997600,
                    reinitialise_params: None,
                }),
                deposit_v7: Some(ContractUpgradeConfig {
                    height: 17010000,
                    reinitialise_params: Some(ReinitialiseParams {
                        withdrawal_period: 461680,
                    }), // https://github.com/Zilliqa/zq2/pull/3221
                }),
            },
            Self::Zq2Mainnet => ContractUpgrades {
                deposit_v3: None,
                deposit_v4: None,
                deposit_v5: Some(ContractUpgradeConfig {
                    height: 0,
                    reinitialise_params: Some(ReinitialiseParams::default()),
                }),
                deposit_v6: Some(ContractUpgradeConfig {
                    height: 13514400,
                    reinitialise_params: None,
                }),
                deposit_v7: Some(ContractUpgradeConfig {
                    height: 13514400,
                    reinitialise_params: Some(ReinitialiseParams {
                        withdrawal_period: 461680,
                    }), // https://github.com/Zilliqa/zq2/pull/3221
                }),
            },
            _ => ContractUpgrades::default(),
        }
    }

    pub fn genesis_fork(&self) -> Option<Value> {
        match self {
            // TODO: Allow missing values from the `genesis_fork` to represent the default behaviour.
            Chain::Zq2Testnet => Some(json!({
                "at_height": 0,
                "executable_blocks": false, // differs from default
                "call_mode_1_sets_caller_to_parent_caller": true,
                "failed_scilla_call_from_gas_exempt_caller_causes_revert": true,
                "scilla_messages_can_call_evm_contracts": true,
                "scilla_contract_creation_increments_account_balance": true,
                "scilla_json_preserve_order": true,
                "scilla_call_respects_evm_state_changes": true,
                "only_mutated_accounts_update_state": true,
                "scilla_call_gas_exempt_addrs": [],
                "scilla_block_number_returns_current_block": true,
                "scilla_maps_are_encoded_correctly": true,
                "transfer_gas_fee_to_zero_account": true,
                "apply_state_changes_only_if_transaction_succeeds": true,
                "apply_scilla_delta_when_evm_succeeded" : true,
                "scilla_deduct_funds_from_actual_sender": true,
                "fund_accounts_from_zero_account": [],
                "scilla_delta_maps_are_applied_correctly": false, // differs from default
                "scilla_server_unlimited_response_size": false, // differs from default
                "scilla_failed_txn_correct_balance_deduction": false,
                "scilla_transition_proper_order": false,
                "evm_to_scilla_value_transfer_zero": false,
                "restore_xsgd_contract": false,
                "evm_exec_failure_causes_scilla_precompile_to_fail": false,
                "revert_restore_xsgd_contract": false,
                "scilla_fix_contract_code_removal_on_evm_tx": false,
                "restore_ignite_wallet_contracts": false,
                "prevent_zil_transfer_from_evm_to_scilla_contract": false,
                "scilla_failed_txn_correct_gas_fee_charged": false,
                "check_minimum_gas_price": false,
                "inject_access_list": false,
                "use_max_gas_priority_fee": false,
                "failed_zil_transfers_to_eoa_proper_fee_deduction": false,
                "validator_jailing": false,
                "scilla_empty_maps_are_encoded_correctly": false,
                "cancun_active": false,
            })),
            Chain::Zq2Mainnet => Some(json!({
                "at_height": 0,
                "executable_blocks": false, // differs from default
                "call_mode_1_sets_caller_to_parent_caller": true,
                "failed_scilla_call_from_gas_exempt_caller_causes_revert": true,
                "scilla_messages_can_call_evm_contracts": true,
                "scilla_contract_creation_increments_account_balance": true,
                "scilla_json_preserve_order": true,
                "scilla_call_respects_evm_state_changes": true,
                "only_mutated_accounts_update_state": true,
                "scilla_call_gas_exempt_addrs": [],
                "scilla_block_number_returns_current_block": true,
                "scilla_maps_are_encoded_correctly": true,
                "transfer_gas_fee_to_zero_account": true,
                "apply_state_changes_only_if_transaction_succeeds": true,
                "apply_scilla_delta_when_evm_succeeded" : true,
                "scilla_deduct_funds_from_actual_sender": true,
                "fund_accounts_from_zero_account": [],
                "scilla_delta_maps_are_applied_correctly": false, // differs from default
                "scilla_server_unlimited_response_size": false, // differs from default
                "scilla_failed_txn_correct_balance_deduction": false,
                "scilla_transition_proper_order": false,
                "evm_to_scilla_value_transfer_zero": false,
                "restore_xsgd_contract": false,
                "evm_exec_failure_causes_scilla_precompile_to_fail": false,
                "revert_restore_xsgd_contract": false,
                "scilla_fix_contract_code_removal_on_evm_tx": false,
                "restore_ignite_wallet_contracts": false,
                "prevent_zil_transfer_from_evm_to_scilla_contract": false,
                "scilla_failed_txn_correct_gas_fee_charged": false,
                "check_minimum_gas_price": false,
                "inject_access_list": false,
                "use_max_gas_priority_fee": false,
                "failed_zil_transfers_to_eoa_proper_fee_deduction": false,
                "validator_jailing": false,
                "scilla_empty_maps_are_encoded_correctly": false,
                "cancun_active": false,
            })),
            _ => None,
        }
    }

    pub fn get_forks(&self) -> Option<Vec<Value>> {
        match self {
            Chain::Zq2Testnet => Some(vec![
                json!({ "at_height": 8099088, "executable_blocks": true }),
                json!({ "at_height": 8371376, "scilla_delta_maps_are_applied_correctly": true }),
                // estimated: 2025-06-27T15:05:14Z
                json!({
                    "at_height": 8377200,
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
                json!({ "at_height": 9340000, "scilla_server_unlimited_response_size": true }),
                // estimated: 2025-07-09T07.00.00Z
                json!({ "at_height": 9341630, "scilla_failed_txn_correct_balance_deduction": true, "scilla_transition_proper_order": true, "evm_to_scilla_value_transfer_zero": true, "restore_xsgd_contract": true }),
                // estimated: 2025-07-11T07.00.00Z
                json!({ "at_height": 9494740, "evm_exec_failure_causes_scilla_precompile_to_fail": true }),
                json!({ "at_height": 9498974, "evm_exec_failure_causes_scilla_precompile_to_fail": false }),
                json!({ "at_height": 9500000, "evm_exec_failure_causes_scilla_precompile_to_fail": true }),
                // estimated: 2025-07-14T12.00.00Z
                json!({ "at_height": 9780700, "revert_restore_xsgd_contract": true, "scilla_fix_contract_code_removal_on_evm_tx": true}),
                // estimated: 2025-07-21T12.00.00Z
                json!({ "at_height": 10109366, "prevent_zil_transfer_from_evm_to_scilla_contract": true}),
                // estimated: 2025-07-28T12.00.00Z
                json!({ "at_height": 10854709, "scilla_failed_txn_correct_gas_fee_charged": true, "check_minimum_gas_price": true}),
                // estimated: 2025-08-02T12.00.00Z
                json!({ "at_height": 11300000, "inject_access_list": true, "use_max_gas_priority_fee": true}),
                // estimated: 2025-08-22T12.00.00Z
                json!({ "at_height": 12998790, "failed_zil_transfers_to_eoa_proper_fee_deduction": true}),
                // estimated: 2025-09-19T12.00.00Z
                json!({ "at_height": 14997600, "validator_jailing": true}),
                // estimated: 2026-01-07T11.00.00Z
                json!({ "at_height": 23080419, "scilla_empty_maps_are_encoded_correctly": true}),
                // estimated: 2026-01-07T11.00.00Z
                json!({ "at_height": 23080419, "cancun_active": true}),
            ]),
            Chain::Zq2Mainnet => Some(vec![
                json!({ "at_height": 4770088, "executable_blocks": true }),
                json!({ "at_height": 4854500, "scilla_delta_maps_are_applied_correctly": true }),
                // estimated: 2025-06-27T15:21:57Z
                json!({
                    "at_height": 4957200,
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
                // estimated: 2025-06-30T14:54:22Z
                json!({ "at_height": 4986000, "scilla_server_unlimited_response_size": true }),
                // estimated: 2025-07-09T12.00.00Z
                json!({ "at_height": 5528557, "scilla_failed_txn_correct_balance_deduction": true, "scilla_transition_proper_order": true, "evm_to_scilla_value_transfer_zero": true, "restore_xsgd_contract": true }),
                // estimated: 2025-07-14T12.00.00Z
                json!({ "at_height": 5910029, "evm_exec_failure_causes_scilla_precompile_to_fail": true, "scilla_fix_contract_code_removal_on_evm_tx": true}),
                // estimated: 2025-07-21T12.00.00Z
                json!({ "at_height": 6283082, "prevent_zil_transfer_from_evm_to_scilla_contract": true, "restore_ignite_wallet_contracts": true}),
                // estimated: 2025-07-29T12.00.00Z
                json!({ "at_height": 6771996, "scilla_failed_txn_correct_gas_fee_charged": true, "check_minimum_gas_price": true}),
                // estimated: 2025-08-04T12.00.00Z
                json!({ "at_height": 7000000, "inject_access_list": true, "use_max_gas_priority_fee": true}),
                // estimated: 2025-09-15T12.00.00Z
                json!({ "at_height": 10153271, "failed_zil_transfers_to_eoa_proper_fee_deduction": true}),
                // estimated: 2025-11-17T07:18:28Z
                json!({ "at_height": 13514400, "validator_jailing": true}),
                // estimated: arbitrary high block number no reachable before next fork
                json!({ "at_height": 99999999, "scilla_empty_maps_are_encoded_correctly": true}),
                // estimated: arbitrary high block number no reachable before next fork
                json!({ "at_height": 99999999, "cancun_active": true}),
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
            format!("Subdomain not available for the chain {self}").red()
        ))
    }

    pub fn get_genesis_amount(&self) -> Result<&'static str> {
        let genesis_amount = self.get_str("genesis_amount");

        if let Some(genesis_amount) = genesis_amount {
            return Ok(genesis_amount);
        }

        Err(anyhow!(
            "{}",
            format!("Genesis amount not available for the chain {self}").red()
        ))
    }

    pub fn get_genesis_deposits_amount(&self) -> Result<&'static str> {
        let genesis_deposits_amount = self.get_str("genesis_deposits_amount");

        if let Some(genesis_deposits_amount) = genesis_deposits_amount {
            return Ok(genesis_deposits_amount);
        }

        Err(anyhow!(
            "{}",
            format!("Genesis deposits amount not available for the chain {self}").red()
        ))
    }

    pub fn get_api_endpoint(&self) -> Result<String> {
        Ok(format!("https://api.{}", self.get_subdomain()?))
    }

    pub fn get_project_id(&self) -> Result<&'static str> {
        let project_id = self.get_str("project_id");

        if let Some(project_id) = project_id {
            println!("{}", format!("Using the project ID {project_id}").green());
            return Ok(project_id);
        }

        Err(anyhow!(
            "{}",
            format!("project_id not available for the chain {self}").red()
        ))
    }

    pub fn get_log_level(&self) -> Result<&'static str> {
        let log_level = self.get_str("log_level");

        Ok(log_level.unwrap_or("zilliqa=trace"))
    }

    pub fn get_enable_kms(&self) -> Result<bool> {
        let enable_kms = self.get_str("enable_kms");
        let enable_kms_bool = enable_kms.unwrap_or("false").to_lowercase() == "true";

        Ok(enable_kms_bool)
    }

    pub fn get_validator_control_address(&self) -> Option<&'static str> {
        self.get_str("validator_control_address")
    }

    pub fn get_new_view_broadcast_interval(&self) -> Option<Duration> {
        Some(Duration::from_secs(30))
    }
}
