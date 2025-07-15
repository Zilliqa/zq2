use std::sync::Arc;

use alloy::{
    primitives::{I256, U256},
    sol_types::{SolValue, abi::Decoder},
};
use anyhow::{Result, anyhow};
use revm::{
    ContextStatefulPrecompile, FrameOrResult, InnerEvmContext,
    handler::register::EvmHandler,
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    precompile::PrecompileError,
    primitives::{
        Address, Bytes, EVMError, LogData, PrecompileErrors, PrecompileOutput, PrecompileResult,
    },
};
use scilla_parser::{
    ast::nodes::{
        NodeAddressType, NodeByteStr, NodeMetaIdentifier, NodeScillaType, NodeTypeMapKey,
        NodeTypeMapValue, NodeTypeMapValueAllowingTypeArguments, NodeTypeNameIdentifier,
    },
    parser::{lexer::Lexer, parser::ScillaTypeParser},
};
use tracing::trace;

use crate::{
    cfg::scilla_ext_libs_path_default,
    constants::SCILLA_INVOKE_RUNNER,
    exec::{ExternalContext, PendingState, ScillaError, scilla_call},
    inspector::ScillaInspector,
    state::Code,
    transaction::{EvmGas, ZilAmount},
};

/// Internal representation of Scilla types. This is a greatly simplified version of [NodeScillaType] (which comes
/// directly from the Scilla parser) and only supports the types we currently care about. Raw parsed types can be
/// converted to a [ScillaType] with a [ToScillaType::to_scilla_type] implementation.
#[derive(Clone, Debug)]
enum ScillaType {
    Map(Box<ScillaType>, Box<ScillaType>),
    ByStr20,
    Int32,
    Int64,
    Int128,
    Int256,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    String,
}

impl ScillaType {
    /// Returns the Scilla representation of this type, assuming it is a transition parameter. Note this may not be
    /// exactly the same as the type in the contract (e.g. `ByStr20 with contract end` types are truncated to just
    /// `ByStr20`).
    fn param_type(&self) -> Option<&'static str> {
        match self {
            ScillaType::ByStr20 => Some("ByStr20"),
            ScillaType::Int32 => Some("Int32"),
            ScillaType::Int64 => Some("Int64"),
            ScillaType::Int128 => Some("Int128"),
            ScillaType::Int256 => Some("Int256"),
            ScillaType::Uint32 => Some("Uint32"),
            ScillaType::Uint64 => Some("Uint64"),
            ScillaType::Uint128 => Some("Uint128"),
            ScillaType::Uint256 => Some("Uint256"),
            ScillaType::String => Some("String"),
            ScillaType::Map(_, _) => None,
        }
    }
}

trait ToScillaType {
    fn to_scilla_type(self) -> Option<ScillaType>;
}

impl ToScillaType for NodeScillaType {
    fn to_scilla_type(self) -> Option<ScillaType> {
        match self {
            NodeScillaType::MapType(k, v) => (k.node, v.node).to_scilla_type(),
            NodeScillaType::GenericTypeWithArgs(ident, args) if args.is_empty() => {
                ident.node.to_scilla_type()
            }
            NodeScillaType::EnclosedType(ty) => ty.node.to_scilla_type(),
            NodeScillaType::ScillaAddresseType(ty) => ty.node.to_scilla_type(),
            _ => None,
        }
    }
}

impl ToScillaType for (NodeTypeMapKey, NodeTypeMapValue) {
    fn to_scilla_type(self) -> Option<ScillaType> {
        let (k, v) = self;
        let k = match k {
            NodeTypeMapKey::GenericMapKey(ident) | NodeTypeMapKey::EnclosedGenericId(ident) => {
                ident.node.to_scilla_type()
            }
            NodeTypeMapKey::AddressMapKeyType(_) | NodeTypeMapKey::EnclosedAddressMapKeyType(_) => {
                None
            }
        }?;
        let v = match v {
            NodeTypeMapValue::MapValueTypeOrEnumLikeIdentifier(ident) => {
                ident.node.to_scilla_type()
            }
            NodeTypeMapValue::MapValueParenthesizedType(ident) => match ident.node {
                NodeTypeMapValueAllowingTypeArguments::TypeMapValueNoArgs(ident) => {
                    match ident.node {
                        NodeTypeMapValue::MapValueTypeOrEnumLikeIdentifier(ident) => {
                            ident.node.to_scilla_type()
                        }
                        NodeTypeMapValue::MapKeyValue(ident) => {
                            (ident.node.key.node, ident.node.value.node).to_scilla_type()
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }?;

        Some(ScillaType::Map(k.into(), v.into()))
    }
}

impl ToScillaType for NodeMetaIdentifier {
    fn to_scilla_type(self) -> Option<ScillaType> {
        match self {
            NodeMetaIdentifier::MetaName(ty) => ty.node.to_scilla_type(),
            _ => None,
        }
    }
}

impl ToScillaType for NodeTypeNameIdentifier {
    fn to_scilla_type(self) -> Option<ScillaType> {
        match self {
            NodeTypeNameIdentifier::ByteStringType(NodeByteStr::Type(s)) => match s.node.as_str() {
                "ByStr20" => Some(ScillaType::ByStr20),
                _ => None,
            },
            NodeTypeNameIdentifier::TypeOrEnumLikeIdentifier(ident) => match ident.node.as_str() {
                "Int32" => Some(ScillaType::Int32),
                "Int64" => Some(ScillaType::Int64),
                "Int128" => Some(ScillaType::Int128),
                "Int256" => Some(ScillaType::Int256),
                "Uint32" => Some(ScillaType::Uint32),
                "Uint64" => Some(ScillaType::Uint64),
                "Uint128" => Some(ScillaType::Uint128),
                "Uint256" => Some(ScillaType::Uint256),
                "String" => Some(ScillaType::String),
                _ => None,
            },
            _ => None,
        }
    }
}

impl ToScillaType for NodeAddressType {
    fn to_scilla_type(self) -> Option<ScillaType> {
        self.identifier.node.to_scilla_type()
    }
}

/// Given a Scilla value of type `ty`, read a Solidity value of this type from the [Decoder] and return the
/// equivalent Scilla value which could be used to look up this key in a map.
fn read_index(ty: ScillaType, d: &mut Decoder) -> Result<Vec<u8>> {
    let index = match ty {
        // Note we use the `Debug` impl of `Address`, rather than `Display` because we don't want to include the EIP-55
        // checksum.
        ScillaType::ByStr20 => {
            serde_json::to_vec(&format!("{:?}", Address::detokenize(d.decode()?)))?
        }
        ScillaType::Int32 => serde_json::to_vec(&i32::detokenize(d.decode()?).to_string())?,
        ScillaType::Int64 => serde_json::to_vec(&i64::detokenize(d.decode()?).to_string())?,
        ScillaType::Int128 => serde_json::to_vec(&i128::detokenize(d.decode()?).to_string())?,
        ScillaType::Int256 => serde_json::to_vec(&I256::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint32 => serde_json::to_vec(&u32::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint64 => serde_json::to_vec(&u64::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint128 => serde_json::to_vec(&u128::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint256 => serde_json::to_vec(&U256::detokenize(d.decode()?).to_string())?,
        ScillaType::String => String::detokenize(d.decode()?).into_bytes(),
        ScillaType::Map(_, _) => {
            return Err(anyhow!("a map cannot be the key of another map"));
        }
    };
    Ok(index)
}

/// Given a scilla type and an EVM ABI decoder, converts the scilla type to a non-map type. The types of map keys will
/// be read from the decoder and the values of those types will be added to `indices`.
///
/// For example, passing `ScillaType::Map(ScillaType::Int32, ScillaType::String)` will read an `int32` from the
/// decoder, add its value to `indices` and return `ScillaType::String`.
fn get_indices(
    ty: ScillaType,
    decoder: &mut Decoder,
    indices: &mut Vec<Vec<u8>>,
) -> Result<ScillaType> {
    match ty {
        ScillaType::Map(k, v) => {
            let index = read_index(*k, decoder)?;
            indices.push(index);
            get_indices(*v, decoder, indices)
        }
        _ => Ok(ty),
    }
}

pub(crate) struct ScillaRead;

#[track_caller]
fn oog<T>() -> Result<T, PrecompileErrors> {
    let location = std::panic::Location::caller();
    trace!(%location, "scilla_call out of gas");
    Err(PrecompileErrors::Error(PrecompileError::OutOfGas))
}

#[track_caller]
fn err<T>(message: impl Into<String>) -> Result<T, PrecompileErrors> {
    let location = std::panic::Location::caller();
    let message = message.into();
    trace!(%location, message, "scilla_call failed");
    Err(err_inner(message))
}

#[track_caller]
fn err_inner(message: impl Into<String>) -> PrecompileErrors {
    let location = std::panic::Location::caller();
    let message = message.into();
    trace!(%location, message, "scilla_call failed");
    PrecompileErrors::Error(PrecompileError::other(message))
}

#[track_caller]
fn fatal<T>(message: &'static str) -> Result<T, PrecompileErrors> {
    let location = std::panic::Location::caller();
    trace!(%location, message, "scilla_call failed");
    Err(PrecompileErrors::Fatal {
        msg: message.to_owned(),
    })
}

// ZQ1 suggests revisiting these costs in the future.
const BASE_COST: u64 = 15;
const PER_BYTE_COST: u64 = 3;

impl ContextStatefulPrecompile<PendingState> for ScillaRead {
    fn call(
        &self,
        input: &Bytes,
        gas_limit: u64,
        context: &mut InnerEvmContext<PendingState>,
    ) -> PrecompileResult {
        let Ok(input_len) = u64::try_from(input.len()) else {
            return err("input too long");
        };
        let required_gas = input_len * PER_BYTE_COST + BASE_COST;
        if gas_limit < required_gas {
            return oog();
        }

        let mut decoder = Decoder::new(input, false);

        let address =
            Address::detokenize(decoder.decode().map_err(|_| err_inner("invalid address"))?);
        let field = String::detokenize(decoder.decode().map_err(|_| err_inner("invalid field"))?);

        let account = match context.db.load_account(address) {
            Ok(account) => account,
            Err(e) => {
                tracing::error!(?e, "state access failed");
                return fatal("state access failed");
            }
        };
        let Code::Scilla {
            ref types,
            ref init_data,
            ..
        } = account.account.code
        else {
            return err(format!("{address} is not a scilla contract"));
        };

        let (ty, init_data_value) = match (
            init_data.iter().find(|p| p.name == field),
            types.get(&field),
        ) {
            // Note that if a field exists in both the `init_data` and mutable fields, we ignore the `init_data` and
            // read from the field. This behaviour matches the semantics of Scilla and specification in ZIP-21.
            (_, Some((ty, _))) => (ty, None),
            (Some(v), None) => (&v.ty, Some(v.value.clone())),
            (None, None) => {
                return err(format!("variable {field} does not exist in contract"));
            }
        };

        let mut errors = vec![];
        let Ok(parsed) = ScillaTypeParser::new().parse(&mut errors, Lexer::new(ty)) else {
            return fatal("failed to parse scilla type");
        };

        let Some(ty) = parsed.node.to_scilla_type() else {
            return err(format!("unsupported scilla type: {ty}"));
        };

        let mut indices = vec![];
        let Ok(ty) = get_indices(ty, &mut decoder, &mut indices) else {
            return err("failed to read indices");
        };

        macro_rules! encoder {
            ($ty:ty) => {{
                if let Some(value) = init_data_value {
                    let Ok(value) = serde_json::from_value::<String>(value) else {
                        return fatal("failed to parse raw value");
                    };
                    let Ok(value) = value.parse::<$ty>() else {
                        return fatal("failed to parse value");
                    };
                    value.abi_encode()
                } else {
                    let Ok(value) = context.db.load_storage(address, &field, &indices) else {
                        return fatal("failed to read value");
                    };
                    if let Some(value) = value {
                        let Ok(value) = serde_json::from_slice::<String>(&value) else {
                            return fatal("failed to parse raw value");
                        };
                        let Ok(value) = value.parse::<$ty>() else {
                            return fatal("failed to parse value");
                        };
                        value.abi_encode()
                    } else {
                        vec![]
                    }
                }
            }};
        }

        let value = match ty {
            ScillaType::ByStr20 => encoder!(Address),
            ScillaType::Int32 => encoder!(i32),
            ScillaType::Int64 => encoder!(i64),
            ScillaType::Int128 => encoder!(i128),
            ScillaType::Int256 => encoder!(I256),
            ScillaType::Uint32 => encoder!(u32),
            ScillaType::Uint64 => encoder!(u64),
            ScillaType::Uint128 => encoder!(u128),
            ScillaType::Uint256 => encoder!(U256),
            ScillaType::String => {
                if let Some(value) = init_data_value {
                    let Ok(value) = serde_json::from_value::<String>(value) else {
                        return fatal("failed to parse raw value");
                    };
                    value.abi_encode()
                } else {
                    let Ok(value) = context.db.load_storage(address, &field, &indices) else {
                        return fatal("failed to read value");
                    };
                    if let Some(value) = value {
                        let Ok(value) = serde_json::from_slice::<String>(value) else {
                            return fatal("failed to parse raw value");
                        };
                        value.abi_encode()
                    } else {
                        vec![]
                    }
                }
            }
            ScillaType::Map(_, _) => unreachable!("map will not be returned from `get_indices`"),
        };

        Ok(PrecompileOutput::new(required_gas, value.into()))
    }
}

pub fn scilla_call_handle_register<I: ScillaInspector>(
    handler: &mut EvmHandler<'_, ExternalContext<I>, PendingState>,
) {
    // Create handler
    let prev_handle = handler.execution.create.clone();
    handler.execution.create = Arc::new(move |ctx, inputs| {
        // Reserve enough space to store the caller.
        ctx.external.callers.reserve(
            (ctx.evm.journaled_state.depth + 1).saturating_sub(ctx.external.callers.len()),
        );
        for _ in ctx.external.callers.len()..(ctx.evm.journaled_state.depth + 1) {
            ctx.external.callers.push(Address::ZERO);
        }
        ctx.external.callers[ctx.evm.journaled_state.depth] = inputs.caller;

        prev_handle(ctx, inputs)
    });

    // Create result handler
    let prev_handle = handler.execution.insert_create_outcome.clone();
    handler.execution.insert_create_outcome = Arc::new(move |ctx, frame, outcome| {
        if outcome.result.is_error() || outcome.result.is_revert() {
            ctx.external.has_evm_failed = true;
        }
        prev_handle(ctx, frame, outcome)
    });

    // EOF create handler
    let prev_handle = handler.execution.eofcreate.clone();
    handler.execution.eofcreate = Arc::new(move |ctx, inputs| {
        // Reserve enough space to store the caller.
        ctx.external.callers.reserve(
            (ctx.evm.journaled_state.depth + 1).saturating_sub(ctx.external.callers.len()),
        );
        for _ in ctx.external.callers.len()..(ctx.evm.journaled_state.depth + 1) {
            ctx.external.callers.push(Address::ZERO);
        }
        ctx.external.callers[ctx.evm.journaled_state.depth] = inputs.caller;

        prev_handle(ctx, inputs)
    });

    // EOF result handler
    let prev_handle = handler.execution.insert_eofcreate_outcome.clone();
    handler.execution.insert_eofcreate_outcome = Arc::new(move |ctx, frame, outcome| {
        if outcome.result.is_error() || outcome.result.is_revert() {
            ctx.external.has_evm_failed = true;
        }
        prev_handle(ctx, frame, outcome)
    });

    // Call handler
    let prev_handle = handler.execution.call.clone();
    handler.execution.call = Arc::new(move |ctx, inputs| {
        // Reserve enough space to store the caller.
        ctx.external.callers.reserve(
            (ctx.evm.journaled_state.depth + 1).saturating_sub(ctx.external.callers.len()),
        );
        for _ in ctx.external.callers.len()..(ctx.evm.journaled_state.depth + 1) {
            ctx.external.callers.push(Address::ZERO);
        }
        ctx.external.callers[ctx.evm.journaled_state.depth] = inputs.caller;

        if inputs.bytecode_address != Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x53") {
            return prev_handle(ctx, inputs);
        }

        let gas = Gas::new(inputs.gas_limit);
        let gas_exempt = ctx
            .external
            .fork
            .scilla_call_gas_exempt_addrs
            .contains(&inputs.caller);

        // Record access of scilla precompile
        ctx.external.has_called_scilla_precompile = true;

        // The behaviour is different for contracts having 21k gas and/or deployed with zq1
        // 1. If gas == 21k and gas_exempt -> allow it to run with gas_left()
        // 2. if precompile failed and gas_exempt -> mark entire txn as failed (not only the current precompile)
        // 3. Otherwise, let it run with what it's given and let the caller decide

        let outcome = scilla_call_precompile(
            &inputs,
            gas.limit(),
            &mut ctx.evm.inner,
            &mut ctx.external,
            gas_exempt,
        );

        // Copied from `EvmContext::call_precompile`
        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas,
            output: Bytes::new(),
        };

        match outcome {
            Ok(output) => {
                if result.gas.record_cost(output.gas_used) {
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
            Err(PrecompileErrors::Fatal { msg }) => return Err(EVMError::Precompile(msg)),
        }

        if ctx
            .external
            .fork
            .failed_scilla_call_from_gas_exempt_caller_causes_revert
        {
            // If precompile failed and this is whitelisted contract -> mark entire transaction as failed
            match result.result {
                InstructionResult::Return => {}
                _ => {
                    if gas_exempt {
                        ctx.external.enforce_transaction_failure = true;
                    }
                }
            }
        }

        Ok(FrameOrResult::new_call_result(
            result,
            inputs.return_memory_offset.clone(),
        ))
    });

    // Call result handler
    let prev_handle = handler.execution.insert_call_outcome.clone();
    handler.execution.insert_call_outcome = Arc::new(move |ctx, frame, memory, outcome| {
        if outcome.result.is_error() || outcome.result.is_revert() {
            ctx.external.has_evm_failed = true;
        }
        prev_handle(ctx, frame, memory, outcome)
    });
}

fn scilla_call_precompile<I: ScillaInspector>(
    input: &CallInputs,
    gas_limit: u64,
    evmctx: &mut InnerEvmContext<PendingState>,
    external_context: &mut ExternalContext<I>,
    gas_exempt: bool,
) -> PrecompileResult {
    let Ok(input_len) = u64::try_from(input.input.len()) else {
        return err("input too long");
    };

    let required_gas = input_len * PER_BYTE_COST + BASE_COST + EvmGas::from(SCILLA_INVOKE_RUNNER).0;

    if !gas_exempt && gas_limit < required_gas {
        return oog();
    }

    let mut decoder = Decoder::new(&input.input, false);

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

    let account = match evmctx.db.pre_state.get_account(address) {
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

            let Ok(value) = read_index(ty, &mut decoder) else {
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

    let empty_state = PendingState::new(evmctx.db.pre_state.clone());
    // Temporarily move the `PendingState` out of `evmctx`, replacing it with an empty state.
    let mut state = std::mem::replace(&mut evmctx.db, empty_state);
    let depth = evmctx.journaled_state.depth;
    if external_context.fork.scilla_call_respects_evm_state_changes {
        state.evm_state = Some(evmctx.journaled_state.clone());
    }

    // 1. if evm_exec_failure_causes_scilla_precompile_to_fail == true then we take converted value
    // 2. if evm_exec_failure_causes_scilla_precompile_to_fail == false and evm_to_scilla_value_transfer_zero == true -> we return 0
    // 3. else we take converted value
    let effective_value = {
        match (
            external_context
                .fork
                .evm_exec_failure_causes_scilla_precompile_to_fail,
            external_context.fork.evm_to_scilla_value_transfer_zero,
        ) {
            (true, _) => ZilAmount::from_amount(input.transfer_value().unwrap_or_default().to()),
            (false, true) => ZilAmount::from_amount(0),
            _ => ZilAmount::from_amount(input.transfer_value().unwrap_or_default().to()),
        }
    };

    let scilla = evmctx.db.pre_state.scilla();
    let Ok((result, mut state)) = scilla_call(
        state,
        scilla,
        evmctx.env.tx.caller,
        if keep_origin {
            if external_context
                .fork
                .call_mode_1_sets_caller_to_parent_caller
            {
                // Use the caller of the parent call-stack.
                external_context.callers[depth - 1]
            } else {
                // Use the original transaction signer.
                evmctx.env.tx.caller
            }
        } else {
            input.caller
        },
        // If this call is gas exempt the gas limit likely is not enough to invoke the Scilla call, therefore we lie
        // and pass a large number instead.
        if gas_exempt {
            EvmGas(u64::MAX).into()
        } else {
            EvmGas(gas_limit - required_gas).into()
        },
        address,
        effective_value,
        serde_json::to_string(&message).unwrap(),
        &mut external_context.inspector,
        &scilla_ext_libs_path_default(),
        external_context.fork,
        evmctx.env.block.number.to(),
    ) else {
        return fatal("scilla call failed");
    };
    trace!(?result, "scilla_call complete");
    if !&result.success {
        evmctx.db = state;
        if result.errors.values().any(|errs| {
            errs.iter()
                .any(|err| matches!(err, ScillaError::GasNotSufficient))
        }) {
            return oog();
        } else {
            return err("scilla call failed");
        }
    }
    state.new_state.retain(|address, account| {
        if !account.touched {
            return true;
        }
        if !account.from_evm {
            return true;
        }

        // Apply changes made to EVM accounts back to the EVM `JournaledState`.
        let before = evmctx.journaled_state.state.get_mut(address).unwrap();

        // The only thing that Scilla is able to update is the balance.
        if before.info.balance.to::<u128>() != account.account.balance {
            before.info.balance = account.account.balance.try_into().unwrap();
            before.mark_touch();
        }

        false
    });
    evmctx.db = state;

    for log in result.logs {
        let log = log.into_evm();
        evmctx.journaled_state.log(alloy::primitives::Log {
            address: log.address,
            data: LogData::new_unchecked(log.topics, log.data.into()),
        });
    }

    // TODO(#767): Handle transfer to Scilla contract if `result.accepted`.

    Ok(PrecompileOutput::new(
        if gas_exempt {
            u64::min(required_gas, gas_limit)
        } else {
            required_gas + result.gas_used.0
        },
        Bytes::new(),
    ))
}
