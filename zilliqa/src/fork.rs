use alloy::{primitives::Address, rlp::Encodable};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::cfg::Amount;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Forks(pub(crate) Vec<Fork>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedSchedule {
    pub file: String,
    pub start_height: u64,
    pub replaced_at: Option<u64>,
}

impl Forks {
    pub fn get(&self, height: u64) -> &Fork {
        let index = self
            .0
            .binary_search_by_key(&height, |f| f.at_height)
            .unwrap_or_else(|i| i - 1);
        &self.0[index]
    }

    pub fn denylisted_accounts_restored_at(&self, height: u64) -> &[(Address, u64)] {
        let first = self
            .0
            .iter()
            .find(|fork| !fork.restore_denylisted_accounts_v1.is_empty())
            .map(|fork| fork.at_height);
        if first != Some(height) {
            return &[];
        }
        self.0
            .iter()
            .rfind(|fork| fork.at_height <= height)
            .map_or(&[], |fork| fork.restore_denylisted_accounts_v1.as_slice())
    }

    pub fn escrow_mintable_admin_at(&self, height: u64) -> Address {
        self.0
            .iter()
            .rfind(|fork| fork.at_height <= height)
            .map(|fork| fork.escrow_mintable_admin)
            .unwrap_or_default()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Fork> {
        self.0.iter()
    }

    pub fn escrow_mintable_admin_change_at(&self, height: u64) -> Option<Address> {
        let before = self.escrow_mintable_admin_at(height.checked_sub(1)?);
        let now = self.escrow_mintable_admin_at(height);
        (now != before).then_some(now)
    }

    pub fn blocked_recipient_schedules(&self) -> Result<Vec<StagedSchedule>> {
        let mut schedules = Vec::new();
        self.staged_schedules(
            "blocked_recipients",
            ("blocked_recipients_file", "blocked_recipients_start_height"),
            |fork| {
                (
                    fork.blocked_recipients_file.as_str(),
                    fork.blocked_recipients_start_height,
                )
            },
            &mut schedules,
        )?;
        self.staged_schedules(
            "blocked_recipients_v2",
            (
                "blocked_recipients_file_v2",
                "blocked_recipients_start_height_v2",
            ),
            |fork| {
                (
                    fork.blocked_recipients_file_v2.as_str(),
                    fork.blocked_recipients_start_height_v2,
                )
            },
            &mut schedules,
        )?;
        self.staged_schedules(
            "blocked_recipients_v3",
            (
                "blocked_recipients_file_v3",
                "blocked_recipients_start_height_v3",
            ),
            |fork| {
                (
                    fork.blocked_recipients_file_v3.as_str(),
                    fork.blocked_recipients_start_height_v3,
                )
            },
            &mut schedules,
        )?;
        self.staged_schedules(
            "blocked_recipients_v4",
            (
                "blocked_recipients_file_v4",
                "blocked_recipients_start_height_v4",
            ),
            |fork| {
                (
                    fork.blocked_recipients_file_v4.as_str(),
                    fork.blocked_recipients_start_height_v4,
                )
            },
            &mut schedules,
        )?;
        Ok(schedules)
    }

    pub fn escrow_lodge_schedules(&self) -> Result<Vec<StagedSchedule>> {
        let mut schedules = Vec::new();
        self.staged_schedules(
            "escrow_lodge",
            ("escrow_lodge_file", "escrow_lodge_start_height"),
            |fork| {
                (
                    fork.escrow_lodge_file.as_str(),
                    fork.escrow_lodge_start_height,
                )
            },
            &mut schedules,
        )?;
        Ok(schedules)
    }

    fn staged_schedules<'a>(
        &'a self,
        what: &str,
        field_names: (&str, &str),
        pair_of: impl Fn(&'a Fork) -> (&'a str, u64),
        schedules: &mut Vec<StagedSchedule>,
    ) -> Result<()> {
        let mut previous: (&str, u64) = ("", 0);
        let mut open: Option<usize> = None;
        for fork in &self.0 {
            let pair = pair_of(fork);
            if pair.0.is_empty() != (pair.1 == 0) {
                return Err(anyhow!(
                    "fork at height {}: {} and {} must be set together",
                    fork.at_height,
                    field_names.0,
                    field_names.1,
                ));
            }
            if pair == previous {
                continue;
            }
            if let Some(index) = open.take() {
                schedules[index].replaced_at = Some(fork.at_height);
            }
            if !pair.0.is_empty() {
                if pair.1 < fork.at_height {
                    return Err(anyhow!(
                        "fork at height {} starts {what} at {}, before its own activation",
                        fork.at_height,
                        pair.1,
                    ));
                }
                if schedules.iter().any(|s| s.file == pair.0) {
                    return Err(anyhow!(
                        "{what} file {} is referenced by two schedules",
                        pair.0,
                    ));
                }
                schedules.push(StagedSchedule {
                    file: pair.0.to_owned(),
                    start_height: pair.1,
                    replaced_at: None,
                });
                open = Some(schedules.len() - 1);
            }
            previous = pair;
        }
        Ok(())
    }

    pub fn find_height_fork_first_activated(&self, fork_name: ForkName) -> Option<u64> {
        let mut sorted_fork = self.0.clone();
        sorted_fork.sort_by_key(|item| item.at_height);
        for fork in sorted_fork.iter() {
            if match fork_name {
                ForkName::ExecutableBlocks => fork.executable_blocks,
                ForkName::FailedScillaCallFromGasExemptCallerCausesRevert => {
                    fork.failed_scilla_call_from_gas_exempt_caller_causes_revert
                }
                ForkName::CallMode1SetsCallerToParentCaller => {
                    fork.call_mode_1_sets_caller_to_parent_caller
                }
                ForkName::ScillaMessagesCanCallEvmContracts => {
                    fork.scilla_messages_can_call_evm_contracts
                }
                ForkName::ScillaContractCreationIncrementsAccountBalance => {
                    fork.scilla_contract_creation_increments_account_balance
                }
                ForkName::ScillaJsonPreserveOrder => fork.scilla_json_preserve_order,
                ForkName::ScillaCallRespectsEvmStateChanges => {
                    fork.scilla_call_respects_evm_state_changes
                }
                ForkName::OnlyMutatedAccountsUpdateState => fork.only_mutated_accounts_update_state,
                ForkName::ScillaCallGasExemptAddrs => {
                    fork.scilla_call_gas_exempt_addrs.length() != 0
                }
                ForkName::ScillaBlockNumberReturnsCurrentBlock => {
                    fork.scilla_block_number_returns_current_block
                }
                ForkName::ScillaMapsAreEncodedCorrectly => fork.scilla_maps_are_encoded_correctly,
                ForkName::FundAccountsFromZeroAccount => {
                    !fork.fund_accounts_from_zero_account.is_empty()
                }
                ForkName::ScillaFailedTxnCorrectBalanceDeduction => {
                    fork.scilla_failed_txn_correct_balance_deduction
                }
                ForkName::ScillaTransitionsProperOrder => fork.scilla_transition_proper_order,
                ForkName::EvmToScillaValueTransferZero => fork.evm_to_scilla_value_transfer_zero,
                ForkName::RestoreXsgdContract => fork.restore_xsgd_contract,
                ForkName::EvmExecFailureCausesScillaWhitelistedAddrToFail => {
                    fork.evm_exec_failure_causes_scilla_precompile_to_fail
                }
                ForkName::RevertRestoreXsgdContract => fork.revert_restore_xsgd_contract,
                ForkName::ScillaFixContractCodeRemovalOnEvmTx => {
                    fork.scilla_fix_contract_code_removal_on_evm_tx
                }
                ForkName::RestoreIgniteWalletContracts => fork.restore_ignite_wallet_contracts,
                ForkName::InjectAccessList => fork.inject_access_list,
                ForkName::UseMaxGasPriorityFee => fork.use_max_gas_priority_fee,
                ForkName::ValidatorJailing => fork.validator_jailing,
                ForkName::ScillaCallGasExemptAddrsV2 => {
                    fork.scilla_call_gas_exempt_addrs_v2.length() != 0
                }
                ForkName::DontOverwriteAccountsFromStaleScillaState => {
                    fork.dont_overwrite_evm_accounts_from_stale_scilla_state
                }
                ForkName::MakeTransfersInScillaPrecompilesWithJournalApi => {
                    fork.make_transfers_in_scilla_precompiles_with_journal_api
                }
                ForkName::DisableInteropNativeZilTransfers0 => {
                    fork.disable_interop_native_zil_transfers_0
                }
                ForkName::TightenPrecompileRules => fork.tighten_precompile_rules,
                ForkName::AllowScillaCallPrecompileToBeCalledFromAddresses => !fork
                    .allow_scilla_call_precompile_to_be_called_from_addresses
                    .is_empty(),
                ForkName::DistributeRewardsEveryEpoch => fork.distribute_rewards_every_epoch,
                ForkName::DeployEscrowContractV1 => fork.deploy_escrow_contract_v1,
                ForkName::DisablePermanentlyScillaPrecompilesV1 => {
                    !fork.disable_permanently_scilla_precompiles_v1.is_empty()
                }
                ForkName::DeployEscrowMintableContractV1 => fork.deploy_escrow_mintable_contract_v1,
            } {
                return Some(fork.at_height);
            }
        }
        None
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Fork {
    pub at_height: u64,
    pub executable_blocks: bool,
    pub failed_scilla_call_from_gas_exempt_caller_causes_revert: bool,
    pub call_mode_1_sets_caller_to_parent_caller: bool,
    pub scilla_messages_can_call_evm_contracts: bool,
    pub scilla_contract_creation_increments_account_balance: bool,
    pub scilla_json_preserve_order: bool,
    pub scilla_call_respects_evm_state_changes: bool,
    pub only_mutated_accounts_update_state: bool,
    pub scilla_call_gas_exempt_addrs: Vec<Address>,
    pub scilla_block_number_returns_current_block: bool,
    pub scilla_maps_are_encoded_correctly: bool,
    pub transfer_gas_fee_to_zero_account: bool,
    pub apply_scilla_delta_when_evm_succeeded: bool,
    pub apply_state_changes_only_if_transaction_succeeds: bool,
    pub scilla_deduct_funds_from_actual_sender: bool,
    pub fund_accounts_from_zero_account: Vec<(Address, Amount)>,
    pub scilla_delta_maps_are_applied_correctly: bool,
    pub scilla_server_unlimited_response_size: bool,
    pub scilla_failed_txn_correct_balance_deduction: bool,
    pub scilla_transition_proper_order: bool,
    pub evm_to_scilla_value_transfer_zero: bool,
    pub restore_xsgd_contract: bool,
    pub evm_exec_failure_causes_scilla_precompile_to_fail: bool,
    pub revert_restore_xsgd_contract: bool,
    pub scilla_fix_contract_code_removal_on_evm_tx: bool,
    pub restore_ignite_wallet_contracts: bool,
    pub prevent_zil_transfer_from_evm_to_scilla_contract: bool,
    pub scilla_failed_txn_correct_gas_fee_charged: bool,
    pub check_minimum_gas_price: bool,
    pub inject_access_list: bool,
    pub use_max_gas_priority_fee: bool,
    pub failed_zil_transfers_to_eoa_proper_fee_deduction: bool,
    pub validator_jailing: bool,
    pub scilla_empty_maps_are_encoded_correctly: bool,
    pub cancun_active: bool,
    pub scilla_call_gas_exempt_addrs_v2: Vec<Address>,
    pub randao_support: bool,
    pub evm_to_scilla_strings_encoded_properly: bool,
    pub dont_overwrite_evm_accounts_from_stale_scilla_state: bool,
    pub make_transfers_in_scilla_precompiles_with_journal_api: bool,
    pub disable_interop_native_zil_transfers_0: bool,
    pub tighten_precompile_rules: bool,
    pub allow_scilla_call_precompile_to_be_called_from_addresses: Vec<Address>,
    pub distribute_rewards_every_epoch: bool,
    pub pectra_active: bool,
    pub disable_zilliqa_txn_execution: bool,
    pub blocked_recipients_start_height: u64,
    pub blocked_recipients_file: String,
    pub blocked_recipients_start_height_v2: u64,
    pub blocked_recipients_file_v2: String,
    pub blocked_recipients_start_height_v3: u64,
    pub blocked_recipients_file_v3: String,
    pub blocked_recipients_start_height_v4: u64,
    pub blocked_recipients_file_v4: String,
    pub zil_transfers_only_to_escrow: bool,
    pub deploy_escrow_contract_v1: bool,
    pub evm_gas_fee_credited_once_to_zero_account: bool,
    pub disable_permanently_scilla_precompiles_v1: Vec<Address>,
    pub deploy_escrow_mintable_contract_v1: bool,
    pub escrow_mintable_admin: Address,
    pub escrow_lodge_start_height: u64,
    pub escrow_lodge_file: String,
    pub invalidate_zq1_staking_contract: Address,
    pub staked_zils_file: String,
    pub restore_denylisted_accounts_v1: Vec<(Address, u64)>,
    pub remove_scilla_contracts_from_evm_delta: bool,
}

pub enum ForkName {
    ExecutableBlocks,
    FailedScillaCallFromGasExemptCallerCausesRevert,
    CallMode1SetsCallerToParentCaller,
    ScillaMessagesCanCallEvmContracts,
    ScillaContractCreationIncrementsAccountBalance,
    ScillaJsonPreserveOrder,
    ScillaCallRespectsEvmStateChanges,
    OnlyMutatedAccountsUpdateState,
    ScillaCallGasExemptAddrs,
    ScillaBlockNumberReturnsCurrentBlock,
    ScillaMapsAreEncodedCorrectly,
    FundAccountsFromZeroAccount,
    ScillaFailedTxnCorrectBalanceDeduction,
    ScillaTransitionsProperOrder,
    EvmToScillaValueTransferZero,
    RestoreXsgdContract,
    EvmExecFailureCausesScillaWhitelistedAddrToFail,
    RevertRestoreXsgdContract,
    ScillaFixContractCodeRemovalOnEvmTx,
    RestoreIgniteWalletContracts,
    InjectAccessList,
    UseMaxGasPriorityFee,
    ValidatorJailing,
    ScillaCallGasExemptAddrsV2,
    DontOverwriteAccountsFromStaleScillaState,
    MakeTransfersInScillaPrecompilesWithJournalApi,
    DisableInteropNativeZilTransfers0,
    TightenPrecompileRules,
    AllowScillaCallPrecompileToBeCalledFromAddresses,
    DistributeRewardsEveryEpoch,
    DeployEscrowContractV1,
    DisablePermanentlyScillaPrecompilesV1,
    DeployEscrowMintableContractV1,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ForkDelta {
    pub at_height: u64,
    pub executable_blocks: Option<bool>,
    pub failed_scilla_call_from_gas_exempt_caller_causes_revert: Option<bool>,
    pub call_mode_1_sets_caller_to_parent_caller: Option<bool>,
    pub scilla_messages_can_call_evm_contracts: Option<bool>,
    pub scilla_contract_creation_increments_account_balance: Option<bool>,
    pub scilla_json_preserve_order: Option<bool>,
    pub scilla_call_respects_evm_state_changes: Option<bool>,
    pub only_mutated_accounts_update_state: Option<bool>,
    #[serde(default)]
    pub scilla_call_gas_exempt_addrs: Vec<Address>,
    pub scilla_block_number_returns_current_block: Option<bool>,
    pub scilla_maps_are_encoded_correctly: Option<bool>,
    pub transfer_gas_fee_to_zero_account: Option<bool>,
    pub apply_scilla_delta_when_evm_succeeded: Option<bool>,
    pub apply_state_changes_only_if_transaction_succeeds: Option<bool>,
    pub scilla_deduct_funds_from_actual_sender: Option<bool>,
    pub fund_accounts_from_zero_account: Option<Vec<(Address, Amount)>>,
    pub scilla_delta_maps_are_applied_correctly: Option<bool>,
    pub scilla_server_unlimited_response_size: Option<bool>,
    pub scilla_failed_txn_correct_balance_deduction: Option<bool>,
    pub scilla_transition_proper_order: Option<bool>,
    pub evm_to_scilla_value_transfer_zero: Option<bool>,
    pub restore_xsgd_contract: Option<bool>,
    pub evm_exec_failure_causes_scilla_precompile_to_fail: Option<bool>,
    pub revert_restore_xsgd_contract: Option<bool>,
    pub scilla_fix_contract_code_removal_on_evm_tx: Option<bool>,
    pub restore_ignite_wallet_contracts: Option<bool>,
    pub prevent_zil_transfer_from_evm_to_scilla_contract: Option<bool>,
    pub scilla_failed_txn_correct_gas_fee_charged: Option<bool>,
    pub check_minimum_gas_price: Option<bool>,
    pub inject_access_list: Option<bool>,
    pub use_max_gas_priority_fee: Option<bool>,
    pub failed_zil_transfers_to_eoa_proper_fee_deduction: Option<bool>,
    pub validator_jailing: Option<bool>,
    pub scilla_empty_maps_are_encoded_correctly: Option<bool>,
    pub cancun_active: Option<bool>,
    #[serde(default)]
    pub scilla_call_gas_exempt_addrs_v2: Vec<Address>,
    pub randao_support: Option<bool>,
    pub evm_to_scilla_strings_encoded_properly: Option<bool>,
    pub dont_overwrite_evm_accounts_from_stale_scilla_state: Option<bool>,
    pub make_transfers_in_scilla_precompiles_with_journal_api: Option<bool>,
    pub disable_interop_native_zil_transfers_0: Option<bool>,
    pub tighten_precompile_rules: Option<bool>,
    pub allow_scilla_call_precompile_to_be_called_from_addresses: Option<Vec<Address>>,
    pub distribute_rewards_every_epoch: Option<bool>,
    pub pectra_active: Option<bool>,
    pub disable_zilliqa_txn_execution: Option<bool>,
    pub blocked_recipients_start_height: Option<u64>,
    pub blocked_recipients_file: Option<String>,
    pub blocked_recipients_start_height_v2: Option<u64>,
    pub blocked_recipients_file_v2: Option<String>,
    pub blocked_recipients_start_height_v3: Option<u64>,
    pub blocked_recipients_file_v3: Option<String>,
    pub blocked_recipients_start_height_v4: Option<u64>,
    pub blocked_recipients_file_v4: Option<String>,
    pub zil_transfers_only_to_escrow: Option<bool>,
    pub deploy_escrow_contract_v1: Option<bool>,
    pub evm_gas_fee_credited_once_to_zero_account: Option<bool>,
    #[serde(default)]
    pub disable_permanently_scilla_precompiles_v1: Vec<Address>,
    pub deploy_escrow_mintable_contract_v1: Option<bool>,
    pub escrow_mintable_admin: Option<Address>,
    pub escrow_lodge_start_height: Option<u64>,
    pub escrow_lodge_file: Option<String>,
    pub invalidate_zq1_staking_contract: Option<Address>,
    pub staked_zils_file: Option<String>,
    pub restore_denylisted_accounts_v1: Option<Vec<(Address, u64)>>,
    pub remove_scilla_contracts_from_evm_delta: Option<bool>,
}

impl Fork {
    pub fn apply_delta_fork(&self, delta: &ForkDelta) -> Fork {
        Fork {
            at_height: delta.at_height,
            executable_blocks: delta.executable_blocks.unwrap_or(self.executable_blocks),
            failed_scilla_call_from_gas_exempt_caller_causes_revert: delta
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
                .unwrap_or(self.failed_scilla_call_from_gas_exempt_caller_causes_revert),
            call_mode_1_sets_caller_to_parent_caller: delta
                .call_mode_1_sets_caller_to_parent_caller
                .unwrap_or(self.call_mode_1_sets_caller_to_parent_caller),
            scilla_messages_can_call_evm_contracts: delta
                .scilla_messages_can_call_evm_contracts
                .unwrap_or(self.scilla_messages_can_call_evm_contracts),
            scilla_contract_creation_increments_account_balance: delta
                .scilla_contract_creation_increments_account_balance
                .unwrap_or(self.scilla_contract_creation_increments_account_balance),
            scilla_json_preserve_order: delta
                .scilla_json_preserve_order
                .unwrap_or(self.scilla_json_preserve_order),
            scilla_call_respects_evm_state_changes: delta
                .scilla_call_respects_evm_state_changes
                .unwrap_or(self.scilla_call_respects_evm_state_changes),
            only_mutated_accounts_update_state: delta
                .only_mutated_accounts_update_state
                .unwrap_or(self.only_mutated_accounts_update_state),
            scilla_call_gas_exempt_addrs: {
                let mut addrs = self.scilla_call_gas_exempt_addrs.clone();
                addrs.extend_from_slice(&delta.scilla_call_gas_exempt_addrs);
                addrs
            },
            scilla_block_number_returns_current_block: delta
                .scilla_block_number_returns_current_block
                .unwrap_or(self.scilla_block_number_returns_current_block),
            scilla_maps_are_encoded_correctly: delta
                .scilla_maps_are_encoded_correctly
                .unwrap_or(self.scilla_maps_are_encoded_correctly),
            transfer_gas_fee_to_zero_account: delta
                .transfer_gas_fee_to_zero_account
                .unwrap_or(self.transfer_gas_fee_to_zero_account),
            apply_scilla_delta_when_evm_succeeded: delta
                .apply_scilla_delta_when_evm_succeeded
                .unwrap_or(self.apply_scilla_delta_when_evm_succeeded),
            apply_state_changes_only_if_transaction_succeeds: delta
                .apply_state_changes_only_if_transaction_succeeds
                .unwrap_or(self.apply_state_changes_only_if_transaction_succeeds),
            scilla_deduct_funds_from_actual_sender: delta
                .scilla_deduct_funds_from_actual_sender
                .unwrap_or(self.scilla_deduct_funds_from_actual_sender),
            fund_accounts_from_zero_account: delta
                .fund_accounts_from_zero_account
                .clone()
                .unwrap_or_default(),
            scilla_delta_maps_are_applied_correctly: delta
                .scilla_delta_maps_are_applied_correctly
                .unwrap_or(self.scilla_delta_maps_are_applied_correctly),
            scilla_server_unlimited_response_size: delta
                .scilla_server_unlimited_response_size
                .unwrap_or(self.scilla_server_unlimited_response_size),
            scilla_failed_txn_correct_balance_deduction: delta
                .scilla_failed_txn_correct_balance_deduction
                .unwrap_or(self.scilla_failed_txn_correct_balance_deduction),
            scilla_transition_proper_order: delta
                .scilla_transition_proper_order
                .unwrap_or(self.scilla_transition_proper_order),
            evm_to_scilla_value_transfer_zero: delta
                .evm_to_scilla_value_transfer_zero
                .unwrap_or(self.evm_to_scilla_value_transfer_zero),
            restore_xsgd_contract: delta
                .restore_xsgd_contract
                .unwrap_or(self.restore_xsgd_contract),
            evm_exec_failure_causes_scilla_precompile_to_fail: delta
                .evm_exec_failure_causes_scilla_precompile_to_fail
                .unwrap_or(self.evm_exec_failure_causes_scilla_precompile_to_fail),
            revert_restore_xsgd_contract: delta
                .revert_restore_xsgd_contract
                .unwrap_or(self.revert_restore_xsgd_contract),
            scilla_fix_contract_code_removal_on_evm_tx: delta
                .scilla_fix_contract_code_removal_on_evm_tx
                .unwrap_or(self.scilla_fix_contract_code_removal_on_evm_tx),
            restore_ignite_wallet_contracts: delta
                .restore_ignite_wallet_contracts
                .unwrap_or(self.restore_ignite_wallet_contracts),
            prevent_zil_transfer_from_evm_to_scilla_contract: delta
                .prevent_zil_transfer_from_evm_to_scilla_contract
                .unwrap_or(self.prevent_zil_transfer_from_evm_to_scilla_contract),
            scilla_failed_txn_correct_gas_fee_charged: delta
                .scilla_failed_txn_correct_gas_fee_charged
                .unwrap_or(self.scilla_failed_txn_correct_gas_fee_charged),
            check_minimum_gas_price: delta
                .check_minimum_gas_price
                .unwrap_or(self.check_minimum_gas_price),
            inject_access_list: delta.inject_access_list.unwrap_or(self.inject_access_list),
            use_max_gas_priority_fee: delta
                .use_max_gas_priority_fee
                .unwrap_or(self.use_max_gas_priority_fee),
            failed_zil_transfers_to_eoa_proper_fee_deduction: delta
                .failed_zil_transfers_to_eoa_proper_fee_deduction
                .unwrap_or(self.failed_zil_transfers_to_eoa_proper_fee_deduction),
            validator_jailing: delta.validator_jailing.unwrap_or(self.validator_jailing),
            scilla_empty_maps_are_encoded_correctly: delta
                .scilla_empty_maps_are_encoded_correctly
                .unwrap_or(self.scilla_empty_maps_are_encoded_correctly),
            cancun_active: delta.cancun_active.unwrap_or(self.cancun_active),
            scilla_call_gas_exempt_addrs_v2: {
                let mut addrs = self.scilla_call_gas_exempt_addrs_v2.clone();
                addrs.extend_from_slice(&delta.scilla_call_gas_exempt_addrs_v2);
                addrs
            },
            randao_support: delta.randao_support.unwrap_or(self.randao_support),
            evm_to_scilla_strings_encoded_properly: delta
                .evm_to_scilla_strings_encoded_properly
                .unwrap_or(self.evm_to_scilla_strings_encoded_properly),
            dont_overwrite_evm_accounts_from_stale_scilla_state: delta
                .dont_overwrite_evm_accounts_from_stale_scilla_state
                .unwrap_or(self.dont_overwrite_evm_accounts_from_stale_scilla_state),
            make_transfers_in_scilla_precompiles_with_journal_api: delta
                .make_transfers_in_scilla_precompiles_with_journal_api
                .unwrap_or(self.make_transfers_in_scilla_precompiles_with_journal_api),
            disable_interop_native_zil_transfers_0: delta
                .disable_interop_native_zil_transfers_0
                .unwrap_or(self.disable_interop_native_zil_transfers_0),
            tighten_precompile_rules: delta
                .tighten_precompile_rules
                .unwrap_or(self.tighten_precompile_rules),
            allow_scilla_call_precompile_to_be_called_from_addresses: delta
                .allow_scilla_call_precompile_to_be_called_from_addresses
                .clone()
                .unwrap_or_else(|| {
                    self.allow_scilla_call_precompile_to_be_called_from_addresses
                        .clone()
                }),
            distribute_rewards_every_epoch: delta
                .distribute_rewards_every_epoch
                .unwrap_or(self.distribute_rewards_every_epoch),
            pectra_active: delta.pectra_active.unwrap_or(self.pectra_active),
            disable_zilliqa_txn_execution: delta
                .disable_zilliqa_txn_execution
                .unwrap_or(self.disable_zilliqa_txn_execution),
            blocked_recipients_start_height: delta
                .blocked_recipients_start_height
                .unwrap_or(self.blocked_recipients_start_height),
            blocked_recipients_file: delta
                .blocked_recipients_file
                .clone()
                .unwrap_or_else(|| self.blocked_recipients_file.clone()),
            blocked_recipients_start_height_v2: delta
                .blocked_recipients_start_height_v2
                .unwrap_or(self.blocked_recipients_start_height_v2),
            blocked_recipients_file_v2: delta
                .blocked_recipients_file_v2
                .clone()
                .unwrap_or_else(|| self.blocked_recipients_file_v2.clone()),
            blocked_recipients_start_height_v3: delta
                .blocked_recipients_start_height_v3
                .unwrap_or(self.blocked_recipients_start_height_v3),
            blocked_recipients_file_v3: delta
                .blocked_recipients_file_v3
                .clone()
                .unwrap_or_else(|| self.blocked_recipients_file_v3.clone()),
            blocked_recipients_start_height_v4: delta
                .blocked_recipients_start_height_v4
                .unwrap_or(self.blocked_recipients_start_height_v4),
            blocked_recipients_file_v4: delta
                .blocked_recipients_file_v4
                .clone()
                .unwrap_or_else(|| self.blocked_recipients_file_v4.clone()),
            zil_transfers_only_to_escrow: delta
                .zil_transfers_only_to_escrow
                .unwrap_or(self.zil_transfers_only_to_escrow),
            deploy_escrow_contract_v1: delta
                .deploy_escrow_contract_v1
                .unwrap_or(self.deploy_escrow_contract_v1),
            evm_gas_fee_credited_once_to_zero_account: delta
                .evm_gas_fee_credited_once_to_zero_account
                .unwrap_or(self.evm_gas_fee_credited_once_to_zero_account),
            disable_permanently_scilla_precompiles_v1: {
                let mut addrs = self.disable_permanently_scilla_precompiles_v1.clone();
                addrs.extend_from_slice(&delta.disable_permanently_scilla_precompiles_v1);
                addrs
            },
            deploy_escrow_mintable_contract_v1: delta
                .deploy_escrow_mintable_contract_v1
                .unwrap_or(self.deploy_escrow_mintable_contract_v1),
            escrow_mintable_admin: delta
                .escrow_mintable_admin
                .unwrap_or(self.escrow_mintable_admin),
            escrow_lodge_start_height: delta
                .escrow_lodge_start_height
                .unwrap_or(self.escrow_lodge_start_height),
            escrow_lodge_file: delta
                .escrow_lodge_file
                .clone()
                .unwrap_or_else(|| self.escrow_lodge_file.clone()),
            invalidate_zq1_staking_contract: delta
                .invalidate_zq1_staking_contract
                .unwrap_or(self.invalidate_zq1_staking_contract),
            staked_zils_file: delta
                .staked_zils_file
                .clone()
                .unwrap_or_else(|| self.staked_zils_file.clone()),
            restore_denylisted_accounts_v1: delta
                .restore_denylisted_accounts_v1
                .clone()
                .unwrap_or_else(|| self.restore_denylisted_accounts_v1.clone()),
            remove_scilla_contracts_from_evm_delta: delta
                .remove_scilla_contracts_from_evm_delta
                .unwrap_or(self.remove_scilla_contracts_from_evm_delta),
        }
    }
}

pub fn genesis_fork_default() -> Fork {
    Fork {
        at_height: 0,
        executable_blocks: true,
        failed_scilla_call_from_gas_exempt_caller_causes_revert: true,
        call_mode_1_sets_caller_to_parent_caller: true,
        scilla_messages_can_call_evm_contracts: true,
        scilla_contract_creation_increments_account_balance: true,
        scilla_json_preserve_order: true,
        scilla_call_respects_evm_state_changes: true,
        only_mutated_accounts_update_state: true,
        scilla_call_gas_exempt_addrs: vec![],
        scilla_block_number_returns_current_block: true,
        scilla_maps_are_encoded_correctly: true,
        transfer_gas_fee_to_zero_account: true,
        apply_scilla_delta_when_evm_succeeded: true,
        apply_state_changes_only_if_transaction_succeeds: true,
        scilla_deduct_funds_from_actual_sender: true,
        fund_accounts_from_zero_account: vec![],
        scilla_delta_maps_are_applied_correctly: true,
        scilla_server_unlimited_response_size: true,
        scilla_failed_txn_correct_balance_deduction: true,
        scilla_transition_proper_order: true,
        evm_to_scilla_value_transfer_zero: true,
        restore_xsgd_contract: true,
        evm_exec_failure_causes_scilla_precompile_to_fail: true,
        revert_restore_xsgd_contract: true,
        scilla_fix_contract_code_removal_on_evm_tx: true,
        restore_ignite_wallet_contracts: true,
        prevent_zil_transfer_from_evm_to_scilla_contract: true,
        scilla_failed_txn_correct_gas_fee_charged: true,
        check_minimum_gas_price: true,
        inject_access_list: true,
        use_max_gas_priority_fee: true,
        failed_zil_transfers_to_eoa_proper_fee_deduction: true,
        validator_jailing: true,
        scilla_empty_maps_are_encoded_correctly: true,
        cancun_active: true,
        scilla_call_gas_exempt_addrs_v2: vec![],
        randao_support: true,
        evm_to_scilla_strings_encoded_properly: true,
        dont_overwrite_evm_accounts_from_stale_scilla_state: true,
        make_transfers_in_scilla_precompiles_with_journal_api: true,
        disable_interop_native_zil_transfers_0: true,
        tighten_precompile_rules: true,
        allow_scilla_call_precompile_to_be_called_from_addresses: vec![],
        distribute_rewards_every_epoch: true,
        pectra_active: true,
        disable_zilliqa_txn_execution: true,
        blocked_recipients_start_height: 0,
        blocked_recipients_file: String::new(),
        blocked_recipients_start_height_v2: 0,
        blocked_recipients_file_v2: String::new(),
        blocked_recipients_start_height_v3: 0,
        blocked_recipients_file_v3: String::new(),
        blocked_recipients_start_height_v4: 0,
        blocked_recipients_file_v4: String::new(),
        zil_transfers_only_to_escrow: false,
        deploy_escrow_contract_v1: false,
        evm_gas_fee_credited_once_to_zero_account: true,
        disable_permanently_scilla_precompiles_v1: vec![],
        deploy_escrow_mintable_contract_v1: false,
        escrow_mintable_admin: Address::ZERO,
        escrow_lodge_start_height: 0,
        escrow_lodge_file: String::new(),
        invalidate_zq1_staking_contract: Address::ZERO,
        staked_zils_file: String::new(),
        restore_denylisted_accounts_v1: vec![],
        remove_scilla_contracts_from_evm_delta: true,
    }
}
