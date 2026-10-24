use std::{collections::BTreeMap, fs, path::Path, sync::MutexGuard};

use alloy::primitives::Address;
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{debug, trace, warn};

use crate::{
    cfg::{Fork, ScillaExtLibsPath, ScillaExtLibsPathInScilla, ScillaExtLibsPathInZq2},
    constants,
    exec::{
        PendingState, ScillaError, ScillaException, ScillaResult, ScillaResultAndState,
        ScillaTransition,
    },
    inspector::ScillaInspector,
    message::BlockHeader,
    scilla::{ParamValue, Scilla},
    state::{Code, ContractInit, ExternalLibrary, State},
    transaction::{EvmGas, ScillaGas, ScillaLog, TxZilliqa, ZilAmount, total_scilla_gas_price},
};

impl State {
    pub(in crate::exec) fn apply_transaction_scilla(
        &mut self,
        from_addr: Address,
        txn: TxZilliqa,
        current_block: BlockHeader,
        inspector: impl ScillaInspector,
    ) -> Result<ScillaResultAndState> {
        let fork = self.forks.get(current_block.number).clone();

        let mut state = PendingState::new(self.try_clone()?, fork.clone());

        let gas_price = txn.gas_price;

        let deposit_gas = txn.get_deposit_gas()?;
        let deposit = total_scilla_gas_price(deposit_gas, gas_price)?;
        trace!("scilla_txn: gas_price {gas_price} deposit_gas {deposit_gas} deposit {deposit}");

        let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
            deposit_gas.into()
        } else {
            EvmGas(0)
        };
        if let Some(result) = state.deduct_from_account(from_addr, deposit, gas_used)? {
            trace!("scilla_txn: Could not deduct deposit");
            return Ok((result, state.finalize()));
        }

        let (result, mut new_state) = if txn.to_addr.is_zero() {
            scilla_create(
                state,
                self.scilla(),
                from_addr,
                txn,
                current_block,
                inspector,
                &self.scilla_ext_libs_path,
                &fork,
            )
        } else {
            scilla_call(
                state,
                self.scilla(),
                from_addr,
                from_addr,
                txn.gas_limit,
                txn.to_addr,
                txn.amount,
                txn.data,
                inspector,
                &self.scilla_ext_libs_path,
                &fork,
                current_block.number,
                false,
            )
        }?;

        let actual_gas_charged =
            total_scilla_gas_price(ScillaGas::from(result.gas_used), gas_price)?;
        let from = new_state.load_account(from_addr)?;
        from.account.nonce += 1;
        from.mark_touch();

        if !fork.scilla_failed_txn_correct_balance_deduction || result.success {
            let to_charge = actual_gas_charged.checked_sub(&deposit);
            trace!("scilla_txn: actual_gas_used {actual_gas_charged} to_charge = {to_charge:?}");
            if let Some(extra_charge) = to_charge {
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    result.gas_used
                } else {
                    EvmGas(0)
                };
                if let Some(result) =
                    new_state.deduct_from_account(from_addr, extra_charge, gas_used)?
                {
                    trace!("scilla_txn: cannot deduct remaining gas - txn failed");
                    let mut failed_state = PendingState::new(self.try_clone()?, fork.clone());
                    return Ok((result, failed_state.finalize()));
                }
            }
        } else {
            let original_acc = self.get_account(from_addr)?;
            from.account.balance = original_acc
                .balance
                .saturating_sub(actual_gas_charged.get()?);
        }
        trace!("scilla_txn completed successfully");
        Ok((result, new_state.finalize()))
    }
}

pub fn zil_contract_address(sender: Address, nonce: u64) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(sender.into_array());
    hasher.update(nonce.to_be_bytes());
    let hashed = hasher.finalize();
    Address::from_slice(&hashed[12..])
}

pub fn store_external_libraries(
    state: &State,
    scilla_ext_libs_path: &ScillaExtLibsPath,
    ext_libraries: Vec<ExternalLibrary>,
) -> Result<(ScillaExtLibsPathInZq2, ScillaExtLibsPathInScilla)> {
    let (ext_libs_dir_in_zq2, ext_libs_dir_in_scilla) =
        scilla_ext_libs_path.generate_random_subdirs();

    let ext_libs_path = Path::new(&ext_libs_dir_in_zq2.0);
    std::fs::create_dir_all(ext_libs_path)?;

    for mut lib in ext_libraries {
        let account = state.get_account(lib.address)?;
        match &account.code {
            Code::Evm(_) => {
                return Err(anyhow!(
                    "Impossible to load an EVM contract as a Scilla library."
                ));
            }
            Code::Scilla {
                code, init_data, ..
            } => {
                let contract_init = ContractInit::new(init_data.clone());
                if !contract_init.is_library()? {
                    return Err(anyhow!(
                        "Impossible to load a non-library contract as a Scilla library."
                    ));
                }

                lib.name.retain(|c| c.is_alphanumeric() || c == '.');
                let file_path = ext_libs_path.join(&lib.name);

                fs::write(&file_path, code).with_context(|| {
                        format!("Failed to write the contract code to {:?}. library name: {}, library address: {}", file_path, lib.name, lib.address)
                    })?;
            }
        }
    }
    Ok((ext_libs_dir_in_zq2, ext_libs_dir_in_scilla))
}

#[allow(clippy::too_many_arguments)]
fn scilla_create(
    mut state: PendingState,
    scilla: MutexGuard<'_, Scilla>,
    from_addr: Address,
    txn: TxZilliqa,
    current_block: BlockHeader,
    mut inspector: impl ScillaInspector,
    scilla_ext_libs_path: &ScillaExtLibsPath,
    fork: &Fork,
) -> Result<(ScillaResult, PendingState)> {
    if txn.data.is_empty() {
        return Err(anyhow!("contract creation without init data"));
    }

    let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
        txn.gas_limit.into()
    } else {
        EvmGas(0)
    };

    if let Some(result) = state.deduct_from_account(from_addr, txn.amount, gas_used)? {
        return Ok((result, state));
    }

    let contract_address = zil_contract_address(from_addr, txn.nonce - 1);

    let mut init_data: Vec<ParamValue> = serde_json::from_str(&txn.data)?;
    if !fork.scilla_json_preserve_order {
        for param_value in init_data.iter_mut() {
            param_value.value.sort_all_objects();
        }
    }

    init_data.extend([
        ParamValue {
            name: "_creation_block".to_string(),
            value: Value::String(current_block.number.to_string()),
            ty: "BNum".to_string(),
        },
        ParamValue {
            name: "_this_address".to_string(),
            value: Value::String(format!("{contract_address:#x}")),
            ty: "ByStr20".to_string(),
        },
    ]);

    let gas = txn.gas_limit;

    let Some(gas) = gas.checked_sub(constants::SCILLA_INVOKE_CHECKER) else {
        warn!("not enough gas to invoke scilla checker");
        let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
            txn.gas_limit.into()
        } else {
            (txn.gas_limit - gas).into()
        };
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used,
                transitions: vec![],
                accepted: Some(false),
                errors: [(0, vec![ScillaError::GasNotSufficient])]
                    .into_iter()
                    .collect(),
                exceptions: vec![],
            },
            state,
        ));
    };

    let contract_init = ContractInit::new(init_data.clone());

    let (ext_libs_dir_in_zq2, ext_libs_dir_in_scilla) = store_external_libraries(
        &state.pre_state,
        scilla_ext_libs_path,
        contract_init.external_libraries()?,
    )?;

    let _cleanup_ext_libs_guard = scopeguard::guard((), |_| {
        let _ = std::fs::remove_dir_all(ext_libs_dir_in_zq2.0);
    });

    let check_output =
        match scilla.check_contract(&txn.code, gas, &contract_init, &ext_libs_dir_in_scilla)? {
            Ok(o) => o,
            Err(e) => {
                warn!(?e, "transaction failed");
                let gas = gas.min(e.gas_remaining);
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: Some(contract_address),
                        logs: vec![],
                        gas_used: (txn.gas_limit - gas).into(),
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(0, vec![ScillaError::CreateContractFailed])]
                            .into_iter()
                            .collect(),
                        exceptions: e.errors.into_iter().map(Into::into).collect(),
                    },
                    state,
                ));
            }
        };

    debug!(?check_output);

    let gas = gas.min(check_output.gas_remaining);

    let contract_info = check_output.contract_info.unwrap_or_default();
    let types = contract_info
        .fields
        .into_iter()
        .map(|p| (p.name, (p.ty, p.depth as u8)))
        .collect();

    let transitions = contract_info.transitions;

    let account = state.load_account(contract_address)?;
    account.mark_touch();
    if fork.scilla_contract_creation_increments_account_balance {
        account.account.balance += txn.amount.get()?;
    } else {
        account.account.balance = txn.amount.get()?;
    }
    account.account.code = Code::Scilla {
        code: txn.code.clone(),
        init_data,
        types,
        transitions,
    };

    let Some(gas) = gas.checked_sub(constants::SCILLA_INVOKE_RUNNER) else {
        warn!("not enough gas to invoke scilla runner");
        let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
            txn.gas_limit.into()
        } else {
            (txn.gas_limit - gas).into()
        };
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used,
                transitions: vec![],
                accepted: Some(false),
                errors: [(0, vec![ScillaError::GasNotSufficient])]
                    .into_iter()
                    .collect(),
                exceptions: vec![],
            },
            state,
        ));
    };

    let (create_output, state) = scilla.create_contract(
        state,
        contract_address,
        &txn.code,
        gas,
        txn.amount,
        &contract_init,
        &ext_libs_dir_in_scilla,
        fork,
        current_block.number,
    )?;
    let create_output = match create_output {
        Ok(o) => o,
        Err(e) => {
            warn!(?e, "transaction failed");
            let gas = gas.min(e.gas_remaining);
            return Ok((
                ScillaResult {
                    success: false,
                    contract_address: Some(contract_address),
                    logs: vec![],
                    gas_used: (txn.gas_limit - gas).into(),
                    transitions: vec![],
                    accepted: Some(false),
                    errors: [(0, vec![ScillaError::CreateContractFailed])]
                        .into_iter()
                        .collect(),
                    exceptions: e.errors.into_iter().map(Into::into).collect(),
                },
                state,
            ));
        }
    };

    debug!(?create_output);

    let gas = gas.min(create_output.gas_remaining);

    inspector.create(from_addr, contract_address, txn.amount.get()?);

    Ok((
        ScillaResult {
            success: true,
            contract_address: Some(contract_address),
            logs: vec![],
            gas_used: (txn.gas_limit - gas).into(),
            transitions: vec![],
            accepted: None,
            errors: BTreeMap::new(),
            exceptions: vec![],
        },
        state,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn scilla_call(
    state: PendingState,
    scilla: MutexGuard<'_, Scilla>,
    from_addr: Address,
    sender: Address,
    gas_limit: ScillaGas,
    to_addr: Address,
    amount: ZilAmount,
    data: String,
    mut inspector: impl ScillaInspector,
    scilla_ext_libs_path: &ScillaExtLibsPath,
    fork: &Fork,
    current_block: u64,
    from_precompile: bool,
) -> Result<(ScillaResult, PendingState)> {
    let mut gas = gas_limit;

    let message = if !data.is_empty() {
        let mut m: Value = serde_json::from_str(&data)?;
        m["_amount"] = amount.to_string().into();
        m["_sender"] = format!("{sender:#x}").into();
        m["_origin"] = format!("{from_addr:#x}").into();
        Some(m)
    } else {
        None
    };

    let mut call_stack = vec![(0, sender, to_addr, amount, message)];
    let mut logs = vec![];
    let mut transitions = vec![];
    let mut root_contract_accepted = false;

    let mut state = Some(state);

    while let Some((depth, sender, to_addr, amount, message)) = call_stack.pop() {
        let mut current_state = state.take().expect("missing state");

        if from_precompile && fork.tighten_precompile_rules && amount != ZilAmount::ZERO {
            return Ok((
                ScillaResult {
                    success: false,
                    contract_address: None,
                    logs: vec![],
                    gas_used: (gas_limit - gas).into(),
                    transitions: vec![],
                    accepted: Some(false),
                    errors: [(depth, vec![ScillaError::CallContractFailed])]
                        .into_iter()
                        .collect(),
                    exceptions: vec![ScillaException {
                        line: 0,
                        message: "ZIL transfer from the scilla_call precompile is not allowed"
                            .to_owned(),
                    }],
                },
                current_state,
            ));
        }

        if from_precompile
            && fork
                .disable_permanently_scilla_precompiles_v1
                .contains(&to_addr)
        {
            return Ok((
                ScillaResult {
                    success: false,
                    contract_address: None,
                    logs: vec![],
                    gas_used: (gas_limit - gas).into(),
                    transitions: vec![],
                    accepted: Some(false),
                    errors: [(depth, vec![ScillaError::CallContractFailed])]
                        .into_iter()
                        .collect(),
                    exceptions: vec![ScillaException {
                        line: 0,
                        message: format!("interop calls to {to_addr} are disabled"),
                    }],
                },
                current_state,
            ));
        }

        let contract = current_state.load_account(to_addr)?;
        let code_and_data = match &contract.account.code {
            Code::Evm(code) if fork.scilla_messages_can_call_evm_contracts || code.is_empty() => {
                None
            }
            Code::Scilla {
                code, init_data, ..
            } => Some((code, init_data)),
            Code::Evm(_) => {
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used: (gas_limit - gas).into(),
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(depth, vec![ScillaError::CallContractFailed])]
                            .into_iter()
                            .collect(),
                        exceptions: vec![ScillaException {
                            line: 0,
                            message: "Scilla call to EVM contract".to_owned(),
                        }],
                    },
                    current_state,
                ));
            }
        };

        if let Some((code, init_data)) = code_and_data {
            let Some(g) = gas.checked_sub(constants::SCILLA_INVOKE_RUNNER) else {
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    gas_limit.into()
                } else {
                    (gas_limit - gas).into()
                };
                warn!("not enough gas to invoke scilla runner");
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used,
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(depth, vec![ScillaError::GasNotSufficient])]
                            .into_iter()
                            .collect(),
                        exceptions: vec![],
                    },
                    current_state,
                ));
            };
            gas = g;

            let code = code.clone();

            let contract_init = ContractInit::new(init_data.clone());

            let contract_balance = contract.account.balance;

            let (ext_libs_dir_in_zq2, ext_libs_dir_in_scilla) = store_external_libraries(
                &current_state.pre_state,
                scilla_ext_libs_path,
                contract_init.external_libraries()?,
            )?;
            let _cleanup_ext_libs_guard = scopeguard::guard((), |_| {
                let _ = std::fs::remove_dir_all(ext_libs_dir_in_zq2.0);
            });
            let (output, mut new_state) = scilla.invoke_contract(
                current_state,
                to_addr,
                &code,
                gas,
                ZilAmount::from_amount(contract_balance),
                &contract_init,
                message
                    .as_ref()
                    .ok_or_else(|| anyhow!("call to a Scilla contract without a message"))?,
                &ext_libs_dir_in_scilla,
                fork,
                current_block,
            )?;
            inspector.call(sender, to_addr, amount.get()?, depth);

            let mut output = match output {
                Ok(o) => o,
                Err(e) => {
                    warn!(?e, "transaction failed");
                    let gas = gas.min(e.gas_remaining);
                    return Ok((
                        ScillaResult {
                            success: false,
                            contract_address: None,
                            logs: vec![],
                            gas_used: (gas_limit - gas).into(),
                            transitions: vec![],
                            accepted: Some(false),
                            errors: [(0, vec![ScillaError::CallContractFailed])]
                                .into_iter()
                                .collect(),
                            exceptions: e.errors.into_iter().map(Into::into).collect(),
                        },
                        new_state,
                    ));
                }
            };

            debug!(?output);

            gas = gas.min(output.gas_remaining);

            if output.accepted {
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    (gas_limit - gas).into()
                } else {
                    EvmGas(0)
                };

                if let Some(result) = new_state.deduct_from_account(sender, amount, gas_used)? {
                    return Ok((result, new_state));
                }

                let to = new_state.load_account(to_addr)?;
                to.mark_touch();
                to.account.balance += amount.get()?;

                if depth == 0 {
                    root_contract_accepted = true;
                }
            }

            transitions.reserve(output.messages.len());
            call_stack.reserve(output.messages.len());

            if fork.scilla_transition_proper_order {
                output.messages.reverse();
            }

            for message in output.messages {
                transitions.push(ScillaTransition {
                    from: to_addr,
                    to: message.recipient,
                    depth: depth + 1,
                    amount: message.amount,
                    tag: message.tag.clone(),
                    params: serde_json::to_string(&message.params)?,
                });

                let next_message = json!({
                    "_tag": message.tag,
                    "_amount": message.amount.to_string(),
                    "_sender": format!("{to_addr:#x}"),
                    "_origin": format!("{from_addr:#x}"),
                    "params": message.params,
                });
                call_stack.push((
                    depth + 1,
                    to_addr,
                    message.recipient,
                    message.amount,
                    Some(next_message),
                ));
            }

            logs.reserve(output.events.len());
            for event in output.events {
                let log = ScillaLog {
                    address: to_addr,
                    event_name: event.event_name,
                    params: event.params,
                };
                logs.push(log);
            }

            state = Some(new_state);
        } else {
            let Some(g) = gas.checked_sub(constants::SCILLA_TRANSFER) else {
                warn!("not enough gas to make transfer");
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    gas_limit.into()
                } else {
                    (gas_limit - gas).into()
                };
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used,
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(0, vec![ScillaError::GasNotSufficient])]
                            .into_iter()
                            .collect(),
                        exceptions: vec![],
                    },
                    current_state,
                ));
            };
            gas = g;

            let deduct_funds_from = match fork.scilla_deduct_funds_from_actual_sender {
                true => sender,
                false => from_addr,
            };

            let gas_left = if fork.scilla_failed_txn_correct_gas_fee_charged {
                gas.into()
            } else {
                EvmGas(0)
            };

            let gas_used = if fork.failed_zil_transfers_to_eoa_proper_fee_deduction {
                EvmGas::from(gas_limit) - gas_left
            } else {
                gas_left
            };

            if let Some(result) =
                current_state.deduct_from_account(deduct_funds_from, amount, gas_used)?
            {
                return Ok((result, current_state));
            }

            let to = current_state.load_account(to_addr)?;
            to.mark_touch();
            to.account.balance += amount.get()?;

            inspector.transfer(from_addr, to_addr, amount.get()?, depth);

            state = Some(current_state);
        }
    }

    Ok((
        ScillaResult {
            success: true,
            contract_address: None,
            logs,
            gas_used: (gas_limit - gas).into(),
            transitions,
            accepted: Some(root_contract_accepted),
            errors: BTreeMap::new(),
            exceptions: vec![],
        },
        state.take().expect("missing state"),
    ))
}
