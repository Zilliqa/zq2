use std::sync::Arc;

use alloy::{
    primitives::{I256, U256},
    sol_types::{abi::Decoder, SolValue},
};
use anyhow::{anyhow, Result};
use revm::{
    handler::register::EvmHandler,
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    precompile::PrecompileError,
    primitives::{
        Address, Bytes, EVMError, LogData, PrecompileErrors, PrecompileOutput, PrecompileResult,
    },
    ContextStatefulPrecompile, FrameOrResult, InnerEvmContext, Inspector,
};
use scilla_parser::{
    ast::nodes::{
        NodeByteStr, NodeMetaIdentifier, NodeScillaType, NodeTypeMapKey, NodeTypeMapValue,
        NodeTypeMapValueAllowingTypeArguments, NodeTypeNameIdentifier,
    },
    parser::{lexer::Lexer, parser::ScillaTypeParser},
};

use crate::{
    exec::{scilla_call, PendingState, ScillaError, SCILLA_INVOKE_RUNNER},
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
            NodeMetaIdentifier::MetaName(ty) => match ty.node {
                NodeTypeNameIdentifier::ByteStringType(NodeByteStr::Type(s)) => {
                    match s.node.as_str() {
                        "ByStr20" => Some(ScillaType::ByStr20),
                        _ => None,
                    }
                }
                NodeTypeNameIdentifier::TypeOrEnumLikeIdentifier(ident) => {
                    match ident.node.as_str() {
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
                    }
                }
                _ => None,
            },
            _ => None,
        }
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

fn oog<T>() -> Result<T, PrecompileErrors> {
    Err(PrecompileErrors::Error(PrecompileError::OutOfGas))
}

fn err<T>(message: impl Into<String>) -> Result<T, PrecompileErrors> {
    Err(PrecompileErrors::Error(PrecompileError::other(message)))
}

fn fatal<T>(message: &'static str) -> Result<T, PrecompileErrors> {
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

        let address = Address::detokenize(decoder.decode().unwrap());
        let field = String::detokenize(decoder.decode().unwrap());

        let Ok(account) = context.db.load_account(address) else {
            return fatal("state access failed");
        };
        let Code::Scilla { ref types, .. } = account.account.code else {
            return err(format!("{address} is not a scilla contract"));
        };
        let Some((ty, _)) = types.get(&field) else {
            return err(format!("variable {field} does not exist in contract"));
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

        macro_rules! decoder {
            ($ty:ty) => {{
                let Ok(value) = context.db.load_storage(address, &field, &indices) else {
                    return fatal("failed to read value");
                };
                let Some(value) = value else {
                    return err("no such value");
                };
                let Ok(value) = serde_json::from_slice::<String>(&value) else {
                    return fatal("failed to parse raw value");
                };
                let Ok(value) = value.parse::<$ty>() else {
                    return fatal("failed to parse value");
                };
                value.abi_encode()
            }};
        }

        let value = match ty {
            ScillaType::ByStr20 => decoder!(Address),
            ScillaType::Int32 => decoder!(i32),
            ScillaType::Int64 => decoder!(i64),
            ScillaType::Int128 => decoder!(i128),
            ScillaType::Int256 => decoder!(I256),
            ScillaType::Uint32 => decoder!(u32),
            ScillaType::Uint64 => decoder!(u64),
            ScillaType::Uint128 => decoder!(u128),
            ScillaType::Uint256 => decoder!(U256),
            ScillaType::String => {
                let Ok(value) = context.db.load_storage(address, &field, &indices) else {
                    return fatal("failed to read value");
                };
                let Some(value) = value else {
                    return err("no such value");
                };
                let Ok(value) = serde_json::from_slice::<String>(value) else {
                    return fatal("failed to parse raw value");
                };
                value.abi_encode()
            }
            ScillaType::Map(_, _) => unreachable!("map will not be returned from `get_indices`"),
        };

        Ok(PrecompileOutput::new(required_gas, value.into()))
    }
}

pub fn scilla_call_handle_register<I: Inspector<PendingState> + ScillaInspector>(
    handler: &mut EvmHandler<'_, I, PendingState>,
) {
    // Call handler
    let prev_handle = handler.execution.call.clone();
    handler.execution.call = Arc::new(move |ctx, inputs| {
        if inputs.bytecode_address != Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL\x53") {
            return prev_handle(ctx, inputs);
        }

        let gas = Gas::new(inputs.gas_limit);
        let outcome =
            scilla_call_precompile(&inputs, gas.limit(), &mut ctx.evm.inner, &mut ctx.external);

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

        Ok(FrameOrResult::new_call_result(
            result,
            inputs.return_memory_offset.clone(),
        ))
    });
}

fn scilla_call_precompile(
    input: &CallInputs,
    gas_limit: u64,
    evmctx: &mut InnerEvmContext<PendingState>,
    inspector: &mut (impl Inspector<PendingState> + ScillaInspector),
) -> PrecompileResult {
    let Ok(input_len) = u64::try_from(input.input.len()) else {
        return err("input too long");
    };
    let required_gas = input_len * PER_BYTE_COST + BASE_COST + EvmGas::from(SCILLA_INVOKE_RUNNER).0;
    if gas_limit < required_gas {
        return oog();
    }

    let mut decoder = Decoder::new(&input.input, false);

    let address = Address::detokenize(decoder.decode().unwrap());
    let transition = String::detokenize(decoder.decode().unwrap());
    let keep_origin = U256::detokenize(decoder.decode().unwrap());

    let keep_origin = if keep_origin == U256::from(0) {
        false
    } else if keep_origin == U256::from(1) {
        true
    } else {
        return err("call mode should be either 0 or 1");
    };

    let Ok(account) = evmctx.db.pre_state.get_account(address) else {
        return fatal("state access failed");
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

            let Ok(value) = read_index(ty, &mut decoder) else {
                return fatal("failed to get value");
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&value) else {
                return fatal("failed to parse value");
            };
            let param = serde_json::json!({"vname": param.name, "type": param.ty, "value": value});

            Ok(param)
        })
        .collect::<Result<_, _>>()?;

    let message = serde_json::json!({"_tag": transition.name, "params": params });

    let empty_state = PendingState::new(evmctx.db.pre_state.clone());
    // Temporarily move the `PendingState` out of `evmctx`, replacing it with an empty state.
    let state = std::mem::replace(&mut evmctx.db, empty_state);
    let scilla = evmctx.db.pre_state.scilla();
    let Ok((result, state)) = scilla_call(
        state,
        scilla,
        evmctx.env.tx.caller,
        if keep_origin {
            evmctx.env.tx.caller
        } else {
            input.caller
        },
        EvmGas(gas_limit - required_gas).into(),
        address,
        ZilAmount::from_amount(input.transfer_value().unwrap_or_default().to()),
        serde_json::to_string(&message).unwrap(),
        inspector,
    ) else {
        return fatal("scilla call failed");
    };
    if !result.success {
        if result
            .errors
            .values()
            .any(|errs| errs.iter().any(|err| matches!(err, ScillaError::OutOfGas)))
        {
            return oog();
        } else {
            return err("scilla call failed");
        }
    }
    // Move the new state back into `evmctx`.
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
        required_gas + result.gas_used.0,
        Bytes::new(),
    ))
}
