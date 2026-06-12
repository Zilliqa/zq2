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
                deposit_v8: Some(ContractUpgradeConfig {
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
                deposit_v8: Some(ContractUpgradeConfig {
                    height: 28278000,
                    reinitialise_params: Some(ReinitialiseParams {
                        withdrawal_period: 461680,
                    }),
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
                deposit_v8: Some(ContractUpgradeConfig {
                    height: 25902000,
                    reinitialise_params: Some(ReinitialiseParams {
                        withdrawal_period: 461680,
                    }),
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
                "scilla_call_gas_exempt_addrs_v2": [],
                "randao_support": false,
                "evm_to_scilla_strings_encoded_properly": false,
                "dont_overwrite_evm_accounts_from_stale_scilla_state": false,
                "make_transfers_in_scilla_precompiles_with_journal_api": false,
                "disable_interop_native_zil_transfers_0": false,
                "tighten_precompile_rules": false,
                "allow_scilla_call_precompile_to_be_called_from_addresses": [],
                "distribute_rewards_every_epoch": false,
                "pectra_active": false,
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
                "scilla_call_gas_exempt_addrs_v2": [],
                "randao_support": false,
                "evm_to_scilla_strings_encoded_properly": false,
                "dont_overwrite_evm_accounts_from_stale_scilla_state": false,
                "make_transfers_in_scilla_precompiles_with_journal_api": false,
                "disable_interop_native_zil_transfers_0": false,
                "tighten_precompile_rules": false,
                "allow_scilla_call_precompile_to_be_called_from_addresses": [],
                "distribute_rewards_every_epoch": false,
                "pectra_active": false,
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
                // estimated: 2026-01-14T11.00.00Z
                json!({ "at_height": 23685219, "scilla_empty_maps_are_encoded_correctly": true}),
                // estimated: 2026-01-14T11.00.00Z
                json!({ "at_height": 23685219, "cancun_active": true}),
                json!({
                    "at_height": 23685219,
                    "scilla_call_gas_exempt_addrs_v2": [
                    ],
                }),
                json!({ "at_height": 28281600, "randao_support": true}),
                json!({ "at_height": 29230131, "evm_to_scilla_strings_encoded_properly": true}),
                json!({ "at_height": 34369689, "dont_overwrite_evm_accounts_from_stale_scilla_state": true}),
                json!({ "at_height": 34369689, "disable_interop_native_zil_transfers_0": true}),
                json!({ "at_height": 34369689, "make_transfers_in_scilla_precompiles_with_journal_api": true}),
                json!({ "at_height": 34369689, "tighten_precompile_rules": true}),
                json!({ "at_height": 34369689, "allow_scilla_call_precompile_to_be_called_from_addresses": ["0x453b11386FBd54bC532892c0217BBc316fc7b918"]}),
                json!({ "at_height": 999999999, "distribute_rewards_every_epoch": true}),
                json!({ "at_height": 999999999, "pectra_active": true}),
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
                // estimated: 2026-02-05T10:00:00Z
                json!({ "at_height": 19486411, "scilla_empty_maps_are_encoded_correctly": true}),
                // estimated: 2026-02-05T10:00:00Z
                json!({ "at_height": 19486411, "cancun_active": true}),
                // estimated: 2026-02-05T10:00:00Z
                json!({
                    "at_height": 19486411,
                    "scilla_call_gas_exempt_addrs_v2": [
                        "0x0F8aeCCaCA7FEE297cC2aBf7fFC9a81e7122A727",
                    ],
                }),
                json!({ "at_height": 25905600, "randao_support": true, "evm_to_scilla_strings_encoded_properly": true}),
                json!({ "at_height": 27081150, "dont_overwrite_evm_accounts_from_stale_scilla_state": true}),
                json!({ "at_height": 27152370, "disable_interop_native_zil_transfers_0": true}),
                json!({ "at_height": 27152370, "make_transfers_in_scilla_precompiles_with_journal_api": true}),
                json!({ "at_height": 27546174, "tighten_precompile_rules": true}),
                json!({
                    "at_height": 29108584,
                    "allow_scilla_call_precompile_to_be_called_from_addresses": [
                        "0x03A79429acc808e4261a68b0117aCD43Cb0FdBfa",
                        "0x9e4E0F7A06E50DA13c78cF8C83E907f792DE54fd",
                        "0xe64cA52EF34FdD7e20C0c7fb2E392cc9b4F6D049",
                        "0xCcF3Ea256d42Aeef0EE0e39Bfc94bAa9Fa14b0Ba",
                        "0xc85b0db68467dede96A7087F4d4C47731555cA7A",
                        "0x8a2afD8Fe79F8C694210eB71f4d726Fc8cAFdB31",
                        "0xD8b73cEd1B16C047048f2c5EA42233DA33168198",
                        "0x737EBf814D2C14fb21E00Fd2990AFc364C2AF506",
                        "0x9C3fE3f471d8380297e4fB222eFb313Ee94DFa0f",
                        "0x7a5A3f96bD3B2c07387d5C9C30ceFDb5543a8ce1",
                        "0x94e18aE7dd5eE57B55f30c4B63E2760c09EFb192",
                        "0x2274005778063684fbB1BfA96a2b725dC37D75f9",
                        "0xa0A5795e7eccc43Ba92d2A0b7804696F8B9e1a05",
                        "0x097C26F8A93009fd9d98561384b5014D64ae17C2",
                        "0xE9df5b4b1134A3aadf693Db999786699B016239e",
                        "0x241c677D9969419800402521ae87C411897A029f",
                        "0x7D2fF48c6b59229d448473D267a714d29F078D3E",
                        "0x40b749DdD5cBeD3706289AD6AD99AE651c16dBE8",
                        "0xFF4CE5aa9B2e8EB6BAB1D220BD39e41B7B79b057",
                        "0x63B991C17010C21250a0eA58C6697F696a48cdf3",
                        "0xE9D47623bb2B3C497668B34fcf61E101a7ea4058",
                        "0x17678B52997B89b179c0a471bF8d266A4A4c6AC5",
                        "0x34f1A58c54B543D6cb82FC63fBc2D39F749099Df",
                        "0xfC7d4Cd4D7bE985b7ACf4a454897Ef978790A2B3",
                        "0x3B78f66651E2eCAbf13977817848F82927a17DcF",
                        "0x6Bb64Ee670060dD71a62aE96A4b6f9F853a4342b",
                        "0x2aE05Bfc681D7872209A3Bf1A9513Bd4A48E66f0",
                        "0x8E3073b22F670d3A09C66D0Abb863f9E358402d2",
                        "0x7F70a752E87372f4270F123bba8d86E432C7fC1D",
                        "0x17D5af5658A24bd964984b36d28e879a8626adC3",
                        "0x9955d33e351a09A0024d484FA1708BFeCdBA05b9",
                        "0xe59f97Fac09ee00AEEF320485ee45D5CcfbBC1E9",
                        "0x860d8A80Cd0EBe10C515024511259C2e779123B1",
                        "0xC5041416D2F4d8c5e874DCFB08322991FA4ACDa9",
                        "0x87f059cb6e481F9CD9a3F92D876DBDc68e30Ea3B",
                        "0xc6F3dede529Af9D98a11C5B32DbF03Bf34272ED5",
                        "0x78871E78385aB7f3295Bb5bEc1d2059acC0114f7",
                        "0x9386c982FCb1aecbD949D04143D8A9E32b4b52bB",
                        "0x5e4a987B04fD59B80976B45D4BB33F2E67A36BD8",
                        "0x29471398a32A03cDe7829D2Bf24fEd531F345578",
                        "0xdB9F6eafD89cC32Aa2C7bD9B67c36BC7B5421cB1",
                        "0x3530D328347baBF925db091bd9524FB1DB782749",
                        "0x849D0AD658e90159D9490b22dED4f7EE583501E6",
                        "0x1D2F988Cbb2d64Cc4bC97f97B174Fa0202d3548F",
                        "0x9121A67cA79B6778eAb477c5F76dF6de7C79cC4b",
                        "0x39135F039a9bB98Ff57b8256551F73FBE7615eFb",
                        "0x2A20d2944e201368e23b9bcE2ebE10CBa8b73E04",
                        "0x2f9A9d490E5615312C50B840DBAdfB9961133cAe",
                        "0xb1bA173026DBC2A56AF63669A402D4C3D7AEEF3E",
                        "0xfE783fbc62A5D47dA47F91A4BAEfE66c7749c643",
                        "0x01b2bcE603387EB22D35B979f2EA2c1f746f8adB",
                        "0xE861c520372Baf02Aaf9356b952dA639D397d64f",
                        "0x65AD8A813EA1582B24324663327d7aab1C5Ac19d",
                        "0x09F522bc8ac879f60f15e5547360b6Bc73ACD139",
                        "0x5A6924462aFc1f059f5c92Ddc9734Ae5404B278B",
                        "0x54bAE118740c2cf68456b547e82572a7752c1b5d",
                        "0x1d6CCF4558d817cc71F142c7e4e1Fa0802ad273e",
                        "0x35A68EE179aA27e4814e7b27A29c9Ba085212945",
                        "0xA44FdeF1F16A7FbC4E86ABe7a0Be1E73C5BE7e0e",
                        "0x11C4F157a53942a2af2009C262A911C437839c18",
                        "0xB861959B443B8fb5a7179a97C136c7F5A9d00Df3",
                        "0x06dA4573BB030f2eE2a5aC6Edbe81A6166Af0C78",
                        "0x07843F245d81E9e6EFaB921C5ce286f67ba6bb40",
                        "0x26F445EBbDDEcB5F0A3660E2810BDCCb0A75Ea70",
                        "0x295eE5c917bb00a80818D93DC5c82Ba36f6CDCcc",
                        "0x310e3f4fA464F335B824E37b588d7bfE51401c9f",
                        "0x5F0776386926e554cb088Df5848Ffd7C5F02eBfA",
                        "0x6400D6Af5D6155FE31e8db3F991B4f9f62c12E74",
                        "0x91158B7B1BB9355371C0C72E4DfD1Ce98D36b29C",
                        "0xdBfE83CeE5D64390d0dE60A363c72D1D98CDF76f",
                        "0xEBFEB37bF5841A60bdfe9B8d980e0746e80E5A8A",
                        "0xf595B5992169439Db1434228bB7fD909C023FeBf",
                        "0xfB6958A64489E82b6c35AD9e5aFE4FcAe127178F",
                        "0x101Bb22C3793617EF2753Ac0E16eCEdea12C6Ad7",
                        "0xb124fbe43ABfF44e48D1FeD892eB01d8dae1ACb4",
                        "0x0101096A36Ff15390614f1C698E50dbb2Da0eeAF",
                        "0x32418cBe4500a73CF713F8bea8416aa861Bbb3fD",
                        "0x4aB91395C08f0eB0AE838f3BAb8F394CE68fD91e",
                        "0x58bd97e17807AA80D0F2373e7249d339930Bd206",
                        "0xe06f86711a744F45eaE97E9B113B1d741c461c98",
                        "0x385a599bc8AC1808B0E61AEF394291a30Be5360a",
                        "0x7C39367cc65d1783A0387601364753ae11C90972",
                        "0x2AF3124E9e75e7F95539063B1322443e5cf389e8",
                        "0x6E08D3C40C8f46Ad8940576d798356763a235D58",
                        "0x1519bc344682FE5ED24813ef57Ad6D5F3433cc2c",
                        "0x1DdB762dD133D035481577AEf6A6334C9FaCa315",
                        "0x480C95c1D81093b127434Ac177C5150F41375138",
                        "0xbC9854943ab565a054800a1D3f50BbAA08Cb59F2",
                        "0x3c8F552EaEc5c5e4eEe55203242AE6bbA09969EF",
                        "0x7bAefF8996101048Ba905dB8695C8f77ae4e7631",
                        "0xD819257C964A78A493DF93D5643E9490b54C5af2",
                        "0x8DEAdC20f7218994c86b59eE1D5c7979fFcAa893",
                        "0xc99ECB82a27B45592eA02ACe9e3C42050f3c00C0",
                        "0x1Ac6790Bb934D4B26DED9FdbE3078850a249af8e",
                        "0x4204D70D27c80d8E1596806620be590d6A1b46A3",
                        "0x2938fF251Aecc1dfa768D7d0276eB6d073690317",
                        "0x4345472A0c6164F35808CDb7e7eCCd3d326CC50b",
                        "0x01035e423c40a9ad4F6be2E6cC014EB5617c8Bd6",
                        "0x20Dd5D5B5d4C72676514A0eA1052d0200003d69D",
                        "0xbfDe2156aF75a29d36614bC1F8005DD816Bd9200",
                    ],
                }),
                json!({ "at_height": 999999999, "distribute_rewards_every_epoch": true}),
                json!({ "at_height": 999999999, "pectra_active": true}),
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
