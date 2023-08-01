use std::ops::Deref;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use evm::backend::Backend;
use evm::executor::stack::MemoryStackSubstate;
use evm::{
    backend::Apply,
    executor::stack::{MemoryStackState, StackSubstateMetadata},
    CreateScheme, Handler,
};
use evm::{Machine, Runtime};
use tracing::{error, info, trace};

use primitive_types::*;

use crate::cps_executor::{CpsCallInterrupt, CpsCreateInterrupt, CpsExecutor, CpsReason};
use crate::precompiles::get_precompiles;
use crate::pretty_printer::log_evm_result;

use crate::protos::evm_proto as EvmProto;

use crate::tracing_logging::{CallContext, LoggingEventListener};

#[allow(clippy::too_many_arguments)]
fn build_exit_result<B: Backend>(
    executor: CpsExecutor<B>,
    runtime: &Runtime,
    trace: &LoggingEventListener,
    exit_reason: evm::ExitReason,
    remaining_gas: u64,
    is_static: bool,
    continuations: Arc<Mutex<EvmProto::Continuations>>,
    _scaling_factor: Option<u64>,
) -> EvmProto::EvmResult {
    let mut result = EvmProto::EvmResult {
        exit_reason: exit_reason.into(),
        return_value: runtime.machine().return_value(),
        ..Default::default()
    };

    let (state_apply, logs) = executor.into_state().deconstruct();

    // Note: If this is a static call, we do not want to modify other continuations' state
    // but if not, then we need to update the state of other continuations if relevant
    result.apply = state_apply
        .into_iter()
        .map(|apply| match apply {
            Apply::Delete { address } => EvmProto::Apply::Delete { address },
            Apply::Modify {
                address,
                basic,
                code,
                storage,
                reset_storage,
            } => EvmProto::Apply::Modify {
                address,
                balance: basic.balance,
                nonce: basic.nonce,
                code: code.unwrap_or_default(),
                storage: storage
                    .into_iter()
                    .map(|(k, v)| {
                        continuations
                            .lock()
                            .unwrap()
                            .update_states(address, k, v, is_static);
                        EvmProto::Storage { key: k, value: v }
                    })
                    .collect(),
                reset_storage,
            },
        })
        .collect();
    result.tx_trace = trace.as_string();
    result.logs = logs.into_iter().collect();
    result.remaining_gas = remaining_gas;
    result
}

#[allow(clippy::too_many_arguments)]
fn build_call_result<B: Backend>(
    executor: CpsExecutor<B>,
    runtime: &Runtime,
    interrupt: CpsCallInterrupt,
    trace: &LoggingEventListener,
    remaining_gas: u64,
    is_static: bool,
    cont_id: u64,
    _scaling_factor: Option<u64>,
) -> EvmProto::EvmResult {
    let mut result = EvmProto::EvmResult {
        return_value: runtime.machine().return_value(),
        ..Default::default()
    };

    let (state_apply, _) = executor.into_state().deconstruct();
    result.apply = state_apply
        .into_iter()
        .map(|apply| match apply {
            Apply::Delete { address } => EvmProto::Apply::Delete { address },
            Apply::Modify {
                address,
                basic,
                code,
                storage,
                reset_storage,
            } => EvmProto::Apply::Modify {
                address,
                balance: basic.balance,
                nonce: basic.nonce,
                code: code.unwrap_or_default(),
                storage: storage
                    .into_iter()
                    .map(|(key, value)| EvmProto::Storage { key, value })
                    .collect(),
                reset_storage,
            },
        })
        .collect();

    result.exit_reason = EvmProto::ExitReasonCps::Trap(EvmProto::Trap::Call);
    result.tx_trace = trace.as_string();
    result.remaining_gas = remaining_gas;

    result.trap_data = Some(EvmProto::TrapData::Call(EvmProto::CallTrap {
        context: EvmProto::Context {
            destination: interrupt.context.address,
            caller: interrupt.context.caller,
            apparent_value: interrupt.context.apparent_value,
        },
        transfer: interrupt.transfer,
        callee_address: interrupt.code_address,
        call_data: interrupt.input,
        is_static: interrupt.is_static || is_static,
        is_precompile: interrupt.is_precompile,
        target_gas: interrupt.target_gas.unwrap_or(u64::MAX),
        memory_offset: interrupt.memory_offset,
        offset_len: interrupt.offset_len,
    }));

    result.continuation_id = cont_id;
    result
}

fn build_create_result(
    runtime: &Runtime,
    interrupt: CpsCreateInterrupt,
    trace: &LoggingEventListener,
    remaining_gas: u64,
    cont_id: u64,
) -> EvmProto::EvmResult {
    let trap_data = Some(EvmProto::TrapData::Create(EvmProto::CreateTrap {
        caller: interrupt.caller,
        scheme: interrupt.scheme,
        value: interrupt.value,
        call_data: interrupt.init_code,
        target_gas: interrupt.target_gas.unwrap_or(u64::MAX),
    }));

    let result = EvmProto::EvmResult {
        return_value: runtime.machine().return_value(),
        exit_reason: EvmProto::ExitReasonCps::Trap(EvmProto::Trap::Create),
        tx_trace: trace.as_string(),
        remaining_gas,
        trap_data,
        continuation_id: cont_id,
        ..Default::default()
    };

    result
}

fn handle_panic(trace: String, remaining_gas: u64, reason: &str) -> EvmProto::EvmResult {
    EvmProto::EvmResult {
        exit_reason: EvmProto::ExitReasonCps::Fatal(evm::ExitFatal::Other(
            reason.to_string().into(),
        )),
        tx_trace: trace,
        remaining_gas,
        ..Default::default()
    }
}

// Convenience fn to hide the evm internals and just
// let you calculate contract address as easily as possible
pub fn calculate_contract_address(address: H160, backend: &impl Backend) -> H160 {
    let config = evm::Config {
        estimate: false,
        call_l64_after_gas: false,
        ..evm::Config::london()
    };

    let metadata = StackSubstateMetadata::new(1, &config);
    let state = MemoryStackState::new(metadata, &backend);
    let precompiles = get_precompiles();

    let mut executor = CpsExecutor::new_with_precompiles(state, &config, &precompiles, true);
    executor.get_create_address(CreateScheme::Legacy { caller: address })
}

pub fn run_evm_impl_direct<B: Backend>(
    args: EvmProto::EvmCallArgs,
    backend: &B,
) -> EvmProto::EvmResult {
    trace!(
        origin = ?backend.origin(),
        address = ?args.address,
        gas_limit = ?args.gas_limit,
        value = ?args.apparent_value,
        estimate = args.estimate,
        is_continuation = args.node_continuation.is_some(),
        cps = args.enable_cps,
        tx_trace = args.tx_trace,
        data = hex::encode(&args.data),
        code = hex::encode(&args.code),
        "running EVM",
    );
    let code = Rc::new(args.code);
    let data = Rc::new(args.data);
    // TODO: handle call_l64_after_gas problem: https://zilliqa-jira.atlassian.net/browse/ZIL-5012
    // todo: this needs to be shanghai...
    let config = evm::Config {
        estimate: args.estimate,
        call_l64_after_gas: false,
        ..evm::Config::london()
    };
    let context = evm::Context {
        address: args.address,
        caller: args.caller,
        apparent_value: args.apparent_value,
    };
    let gas_limit = args.gas_limit * args.gas_scaling_factor;
    let metadata = StackSubstateMetadata::new(gas_limit, &config);
    // Check if evm should resume from the point it stopped
    let (feedback_continuation, mut runtime, state) =
        if let Some(continuation) = args.node_continuation {
            let recorded_cont = args
                .continuations
                .lock()
                .unwrap()
                .get_contination(continuation.id);
            if recorded_cont.is_none() {
                let result = handle_panic(
                    args.tx_trace,
                    gas_limit,
                    format!("Continuation not found! Id: {:?}", continuation.id).as_str(),
                );
                return result;
            }

            let recorded_cont = recorded_cont.unwrap();

            let machine = Machine::create_from_state(
                Rc::new(recorded_cont.code),
                Rc::new(recorded_cont.data),
                recorded_cont.position,
                recorded_cont.return_range,
                recorded_cont.valids,
                recorded_cont.memory,
                recorded_cont.stack,
            );
            let runtime = Runtime::new_from_state(machine, context, &config);
            let memory_substate = MemoryStackSubstate::from_state(
                metadata,
                recorded_cont.logs,
                recorded_cont.accounts,
                recorded_cont.storages,
                recorded_cont.deletes,
            );
            let state = MemoryStackState::new_with_substate(memory_substate, &backend);
            (Some(continuation), runtime, state)
        } else {
            let runtime = evm::Runtime::new(code, data.clone(), context, &config);
            let state = MemoryStackState::new(metadata, &backend);
            (None, runtime, state)
        };
    // Scale the gas limit.

    let precompiles = get_precompiles();

    let mut executor =
        CpsExecutor::new_with_precompiles(state, &config, &precompiles, args.enable_cps);

    let mut listener;

    if args.tx_trace.is_empty() {
        listener = LoggingEventListener::new(args.tx_trace_enabled);
    } else {
        listener = serde_json::from_str(&args.tx_trace).unwrap()
    }

    // If there is no continuation, we need to push our call context on,
    // Otherwise, our call context is loaded and is last element in stack
    if feedback_continuation.is_none() {
        let mut call = CallContext::new();
        call.call_type = "CALL".to_string();
        let apparent_value = args.apparent_value;
        call.value = format!("0x{apparent_value}");
        call.gas = format!("0x{gas_limit:x}"); // Gas provided for call
        call.input = format!("0x{}", hex::encode(data.deref()));

        if listener.call_tracer.is_empty() {
            call.from = format!("{:?}", backend.origin());
        } else {
            call.from = listener.call_tracer.last().unwrap().to.clone();
        }

        let address = args.address;
        call.to = format!("{address:?}");
        listener.push_call(call);
    }

    // We have to catch panics, as error handling in the Backend interface of
    // do not have Result, assuming all operations are successful.
    //
    // We are asserting it is safe to unwind, as objects will be dropped after
    // the unwind.
    let executor_result = panic::catch_unwind(AssertUnwindSafe(|| {
        evm::runtime::tracing::using(&mut listener, || {
            executor.execute(&mut runtime, feedback_continuation)
        })
    }));

    // Scale back remaining gas to Scilla units (no rounding!).
    let remaining_gas = executor.gas() / args.gas_scaling_factor;

    // Update the traces
    listener.raw_tracer.return_value = hex::encode(runtime.machine().return_value());
    listener.raw_tracer.gas = gas_limit - remaining_gas;
    if !listener.call_tracer.is_empty() {
        listener.call_tracer.last_mut().unwrap().gas_used =
            format!("0x{:x}", gas_limit - remaining_gas);
        listener.call_tracer.last_mut().unwrap().output =
            format!("0x{}", hex::encode(runtime.machine().return_value()));
    }

    if let Err(panic) = executor_result {
        let panic_message = panic
            .downcast::<String>()
            .unwrap_or_else(|_| Box::new("unknown panic".to_string()));
        error!("EVM panicked: '{:?}'", panic_message);
        let result = handle_panic(listener.as_string(), remaining_gas, &panic_message);
        return result;
    }

    let cps_result = executor_result.unwrap();

    let result = match cps_result {
        CpsReason::NormalExit(exit_reason) => {
            // Normal exit, we finished call.
            listener.finished_call();

            match exit_reason {
                evm::ExitReason::Revert(_) => {
                    listener.otter_transaction_error =
                        format!("0x{}", hex::encode(runtime.machine().return_value()));
                    info!("Tx reverted: {:?}", runtime.machine().return_value());
                }
                _ => {
                    trace!(
                        position = ?runtime.machine().position(),
                        memory = hex::encode(runtime.machine().memory().data()),
                        stack = ?runtime.machine().stack().data(),
                        "machine exited",
                    );
                }
            }

            build_exit_result(
                executor,
                &runtime,
                &listener,
                exit_reason,
                remaining_gas,
                args.is_static,
                args.continuations,
                args.scaling_factor,
            )
        }
        CpsReason::CallInterrupt(i) => {
            let cont_id = args
                .continuations
                .lock()
                .unwrap()
                .create_continuation(runtime.machine_mut(), executor.state().substate());

            build_call_result(
                executor,
                &runtime,
                i,
                &listener,
                remaining_gas,
                args.is_static,
                cont_id,
                args.scaling_factor,
            )
        }
        CpsReason::CreateInterrupt(i) => {
            let cont_id = args
                .continuations
                .lock()
                .unwrap()
                .create_continuation(runtime.machine_mut(), executor.into_state().substate());

            build_create_result(&runtime, i, &listener, remaining_gas, cont_id)
        }
    };

    trace!(
        context = ?args.evm_context,
        origin = ?backend.origin(),
        address = ?args.address,
        gas_limit = args.gas_limit,
        value = ?args.apparent_value,
        data = hex::encode(data.deref()),
        estimate = args.estimate,
        cps = args.enable_cps,
        result = log_evm_result(&result),
        return_value = hex::encode(runtime.machine().return_value()),
        "execution completed",
    );

    result
}
