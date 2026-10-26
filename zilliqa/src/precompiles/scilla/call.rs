use alloy::{
    primitives::U256,
    sol_types::{SolValue, abi::Decoder},
};
use revm::{
    context_interface::ContextTr,
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    primitives::{Address, Bytes, LogData},
};
use revm_context::JournalTr;
use revm_inspector::JournalExt;
use revm_precompile::PrecompileOutput;
use scilla_parser::parser::{lexer::Lexer, parser::ScillaTypeParser};
use tracing::trace;

use super::{
    BASE_COST, PER_BYTE_COST, PrecompileErrors, err, err_inner, fatal, interop_disabled_for_target,
    oog,
    types::{ToScillaType, read_index},
};
use crate::{
    cfg::scilla_ext_libs_path_default,
    constants::SCILLA_INVOKE_RUNNER,
    evm::ZQ2EvmContext,
    exec::{PendingState, ScillaError, ScillaResult, scilla_call},
    precompiles::ContextPrecompile,
    state::Code,
    transaction::{EvmGas, ScillaGas, ZilAmount},
};

pub struct ScillaCall;

impl ContextPrecompile for ScillaCall {
    fn call(
        &self,
        ctx: &mut ZQ2EvmContext,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        let gas = Gas::new(inputs.gas_limit);

        if interop_disabled_for_target(ctx, inputs) {
            ctx.chain.enforce_transaction_failure = true;
            return Ok(Some(InterpreterResult {
                result: InstructionResult::PrecompileError,
                gas,
                output: Bytes::new(),
            }));
        }

        ctx.chain.has_called_scilla_precompile = true;

        if inputs.is_static && ctx.chain.fork.tighten_precompile_rules {
            ctx.chain.enforce_transaction_failure = true;
            return Ok(Some(InterpreterResult {
                result: InstructionResult::PrecompileError,
                gas,
                output: Bytes::new(),
            }));
        }

        let allowlist = &ctx
            .chain
            .fork
            .allow_scilla_call_precompile_to_be_called_from_addresses;
        if !allowlist.is_empty() && !allowlist.contains(&inputs.caller) {
            ctx.chain.enforce_transaction_failure = true;
            return Ok(Some(InterpreterResult {
                result: InstructionResult::PrecompileError,
                gas,
                output: Bytes::new(),
            }));
        }

        let gas_exempt = ctx
            .chain
            .fork
            .scilla_call_gas_exempt_addrs
            .contains(&inputs.caller)
            || ctx
                .chain
                .fork
                .scilla_call_gas_exempt_addrs_v2
                .contains(&inputs.caller);

        let outcome = scilla_call_precompile(inputs, gas.limit(), ctx, gas_exempt);

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas,
            output: Bytes::new(),
        };

        match outcome {
            Ok(output) => {
                if result.gas.record_regular_cost(output.gas_used) {
                    result.result = InstructionResult::Return;
                    result.output = output.bytes;
                } else {
                    result.result = InstructionResult::PrecompileOOG;
                }
            }
            Err(PrecompileErrors::Error(e)) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
            }
            Err(PrecompileErrors::Fatal { msg }) => return Err(msg),
        }

        if ctx
            .chain
            .fork
            .failed_scilla_call_from_gas_exempt_caller_causes_revert
        {
            match result.result {
                InstructionResult::Return => {}
                _ => {
                    if gas_exempt {
                        ctx.chain.enforce_transaction_failure = true;
                    }
                }
            }
        }

        if ctx.chain.fork.tighten_precompile_rules
            && !matches!(result.result, InstructionResult::Return)
        {
            ctx.chain.enforce_transaction_failure = true;
        }

        Ok(Some(result))
    }
}

fn scilla_call_precompile(
    input: &CallInputs,
    gas_limit: u64,
    ctx: &mut ZQ2EvmContext,
    gas_exempt: bool,
) -> std::result::Result<PrecompileOutput, PrecompileErrors> {
    if ctx.chain.fork.disable_interop_native_zil_transfers_0 && !input.value.get().is_zero() {
        return err("native ZIL transfers to the scilla_call precompile are disabled");
    }

    let Ok(input_len) = u64::try_from(input.input.len()) else {
        return err("input too long");
    };

    let required_gas = input_len * PER_BYTE_COST + BASE_COST + EvmGas::from(SCILLA_INVOKE_RUNNER).0;

    if !gas_exempt && gas_limit < required_gas {
        return oog();
    }

    let bytes_input = input.input.bytes(ctx);
    let mut decoder = Decoder::new(&bytes_input);

    let address = Address::detokenize(decoder.decode().map_err(|_| err_inner("invalid address"))?);
    let transition = String::detokenize(
        decoder
            .decode()
            .map_err(|_| err_inner("invalid transition"))?,
    );
    let keep_origin = U256::detokenize(
        decoder
            .decode()
            .map_err(|_| err_inner("invalid keep_origin"))?,
    );

    let keep_origin = if keep_origin == U256::from(0) {
        false
    } else if keep_origin == U256::from(1) {
        true
    } else {
        return err("call mode should be either 0 or 1");
    };
    trace!(%address, transition, %keep_origin, "scilla_call");

    let account = match ctx.journal().db().pre_state.get_account(address) {
        Ok(account) => account,
        Err(e) => {
            tracing::error!(?e, "state access failed");
            return fatal("state access failed");
        }
    };
    let Code::Scilla { transitions, .. } = account.code else {
        return err(format!("{address} is not a scilla contract"));
    };
    let Some(transition) = transitions.into_iter().find(|t| t.name == transition) else {
        return err(format!(
            "transition {transition} does not exist in contract"
        ));
    };

    if ctx.chain.fork.tighten_precompile_rules {
        let min_head = (3 + transition.params.len()) * 32;
        let transition_offset = U256::from_be_slice(&bytes_input[32..64]);
        if transition_offset < U256::from(min_head as u64) {
            return err("scilla_call calldata omits transition parameters");
        }
    }

    let params: Vec<_> = transition
        .params
        .into_iter()
        .map(|param| {
            let mut errors = vec![];
            let Ok(parsed) = ScillaTypeParser::new().parse(&mut errors, Lexer::new(&param.ty))
            else {
                return fatal("failed to parse parameter type");
            };

            let Some(ty) = parsed.node.to_scilla_type() else {
                return err(format!("unsupported scilla type: {}", param.ty));
            };
            let Some(param_type) = ty.param_type() else {
                return err(format!("unexpected scilla type as a parameter: {ty:?}"));
            };

            let Ok(value) = read_index(ty, &mut decoder, &ctx.chain.fork) else {
                return fatal("failed to get value");
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&value) else {
                return fatal("failed to parse value");
            };
            let param =
                serde_json::json!({"vname": param.name, "type": param_type, "value": value});

            Ok(param)
        })
        .collect::<Result<_, _>>()?;

    let message = serde_json::json!({"_tag": transition.name, "params": params });

    let depth = ctx.journal().depth;
    let sender = if keep_origin {
        if ctx.chain.fork.call_mode_1_sets_caller_to_parent_caller && depth >= 2 {
            ctx.chain.callers[depth - 2]
        } else {
            ctx.tx.caller
        }
    } else {
        input.caller
    };

    let effective_value = {
        match (
            ctx.chain
                .fork
                .evm_exec_failure_causes_scilla_precompile_to_fail,
            ctx.chain.fork.evm_to_scilla_value_transfer_zero,
        ) {
            (true, _) => ZilAmount::from_amount(input.call_value().to()),
            (false, true) => ZilAmount::from_amount(0),
            _ => ZilAmount::from_amount(input.call_value().to()),
        }
    };

    let effective_value_get = effective_value
        .get()
        .map_err(|e| PrecompileErrors::Fatal { msg: e.to_string() })?;
    if effective_value_get > 0 {
        if ctx
            .chain
            .fork
            .make_transfers_in_scilla_precompiles_with_journal_api
        {
            match ctx.journal_mut().transfer(
                input.target_address,
                sender,
                U256::from(effective_value_get),
            ) {
                Ok(None) => {}
                Ok(Some(e)) => return err(format!("scilla precompile refund failed: {e:?}")),
                Err(e) => {
                    tracing::error!(?e, "state access failed");
                    return fatal("state access failed");
                }
            }
        } else {
            let evm_state = ctx.journal_mut().evm_state_mut();
            let precompile_acc = evm_state.get_mut(&input.target_address).unwrap();
            precompile_acc.info.balance = precompile_acc
                .info
                .balance
                .saturating_sub(U256::from(effective_value_get));
            let sender_acc = evm_state.get_mut(&sender).unwrap();
            sender_acc.info.balance += U256::from(effective_value_get);
        }
    }

    let gas = if gas_exempt {
        EvmGas(u64::MAX).into()
    } else {
        EvmGas(gas_limit - required_gas).into()
    };
    let result = handoff_legacy(ctx, input, address, sender, gas, effective_value, &message)?;

    for log in result.logs {
        let log = log.into_evm();
        ctx.journaled_state.log(alloy::primitives::Log {
            address: log.address,
            data: LogData::new_unchecked(log.topics, log.data.into()),
        });
    }

    Ok(PrecompileOutput::new(
        if gas_exempt {
            u64::min(required_gas, gas_limit)
        } else {
            required_gas + result.gas_used.0
        },
        Bytes::default(),
        0,
    ))
}

fn handoff_legacy(
    ctx: &mut ZQ2EvmContext,
    input: &CallInputs,
    address: Address,
    sender: Address,
    gas: ScillaGas,
    effective_value: ZilAmount,
    message: &serde_json::Value,
) -> std::result::Result<ScillaResult, PrecompileErrors> {
    let empty_state =
        PendingState::new(ctx.journal().db().pre_state.clone(), ctx.chain.fork.clone());
    let mut state = std::mem::replace(&mut ctx.journaled_state.database, empty_state);

    if ctx.chain.fork.scilla_call_respects_evm_state_changes {
        state.evm_state = Some(ctx.journal().evm_state().clone());
    }

    let scilla = ctx.journaled_state.database.pre_state.scilla();

    let Ok((result, mut state)) = scilla_call(
        state,
        scilla,
        input.caller,
        sender,
        gas,
        address,
        effective_value,
        serde_json::to_string(message).unwrap(),
        &mut ctx.chain.touched_address_inspector,
        &scilla_ext_libs_path_default(),
        &ctx.chain.fork,
        ctx.block.number.to(),
        true,
    ) else {
        return fatal("scilla call failed");
    };
    trace!(?result, "scilla_call complete");
    if !&result.success {
        ctx.journaled_state.database = state;
        if result.errors.values().any(|errs| {
            errs.iter()
                .any(|err| matches!(err, ScillaError::GasNotSufficient))
        }) {
            return oog();
        } else {
            return err("scilla call failed");
        }
    }
    let mut evm_account_updates = Vec::new();
    state.new_state.retain(|address, account| {
        if !account.touched {
            return true;
        }
        if !account.from_evm {
            return true;
        }
        evm_account_updates.push((*address, account.account.balance));
        false
    });

    for (address, target_balance) in evm_account_updates {
        if ctx
            .chain
            .fork
            .make_transfers_in_scilla_precompiles_with_journal_api
        {
            let current = ctx
                .journal_mut()
                .state
                .get(&address)
                .map(|a| a.info.balance)
                .unwrap_or_default();
            let target = U256::from(target_balance);
            if target > current {
                ctx.journal_mut()
                    .balance_incr(address, target - current)
                    .map_err(|e| {
                        tracing::error!(?e, "state access failed");
                        PrecompileErrors::Fatal {
                            msg: "state access failed".to_string(),
                        }
                    })?;
            } else if current > target
                && let Some(transfer_err) = ctx
                    .journal_mut()
                    .transfer(address, input.target_address, current - target)
                    .map_err(|e| {
                        tracing::error!(?e, "state access failed");
                        PrecompileErrors::Fatal {
                            msg: "state access failed".to_string(),
                        }
                    })?
            {
                return err(format!(
                    "scilla precompile balance reconciliation failed: {transfer_err:?}"
                ));
            }
        } else {
            let before = ctx.journal_mut().state.get_mut(&address).unwrap();
            if before.info.balance.to::<u128>() != target_balance {
                before.info.balance = target_balance.try_into().unwrap();
                before.mark_touch();
            }
        }
    }
    ctx.journaled_state.database = state;

    Ok(result)
}
