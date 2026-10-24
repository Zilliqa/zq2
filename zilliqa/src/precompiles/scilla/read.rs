use alloy::{
    primitives::{Address, I256, U256},
    sol_types::{SolValue, abi::Decoder},
};
use revm::{
    context_interface::ContextTr,
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    primitives::Bytes,
};
use revm_context::JournalTr;
use revm_precompile::PrecompileOutput;
use scilla_parser::parser::{lexer::Lexer, parser::ScillaTypeParser};

use super::{
    BASE_COST, PER_BYTE_COST, PrecompileErrors, err, err_inner, fatal, interop_disabled_for_target,
    oog,
    types::{ScillaType, ToScillaType, get_indices},
};
use crate::{evm::ZQ2EvmContext, precompiles::ContextPrecompile, state::Code};

pub struct ScillaRead;

impl ContextPrecompile for ScillaRead {
    fn call(
        &self,
        ctx: &mut ZQ2EvmContext,
        inputs: &CallInputs,
    ) -> std::result::Result<Option<InterpreterResult>, String> {
        let gas = Gas::new(inputs.gas_limit);

        if interop_disabled_for_target(ctx, inputs) {
            ctx.chain.enforce_transaction_failure = true;
            return Ok(Some(InterpreterResult {
                result: InstructionResult::PrecompileError,
                gas,
                output: Bytes::new(),
            }));
        }

        let outcome = scilla_read(inputs, gas.limit(), ctx);

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

        Ok(Some(result))
    }
}

fn scilla_read(
    input: &CallInputs,
    gas_limit: u64,
    ctx: &mut ZQ2EvmContext,
) -> std::result::Result<PrecompileOutput, PrecompileErrors> {
    let Ok(input_len) = u64::try_from(input.input.len()) else {
        return err("input too long");
    };

    let required_gas = input_len * PER_BYTE_COST + BASE_COST;
    if gas_limit < required_gas {
        return oog();
    }

    let raw_input = input.input.bytes(ctx);

    let mut decoder = Decoder::new(&raw_input);

    let address = Address::detokenize(decoder.decode().map_err(|_| err_inner("invalid address"))?);
    let field = String::detokenize(decoder.decode().map_err(|_| err_inner("invalid field"))?);

    let field_info = match ctx.db_mut().load_account(address) {
        Ok(account) => field_type(&account.account.code, address, &field),
        Err(e) => {
            tracing::error!(?e, "state access failed");
            return fatal("state access failed");
        }
    };
    let (ty, init_data_value) = field_info?;
    let ty = &ty;

    let mut errors = vec![];
    let Ok(parsed) = ScillaTypeParser::new().parse(&mut errors, Lexer::new(ty)) else {
        return fatal("failed to parse scilla type");
    };

    let Some(ty) = parsed.node.to_scilla_type() else {
        return err(format!("unsupported scilla type: {ty}"));
    };

    let mut indices = vec![];
    let Ok(ty) = get_indices(ty, &mut decoder, &mut indices, &ctx.chain.fork) else {
        return err("failed to read indices");
    };

    let stored_value = if init_data_value.is_some() {
        None
    } else {
        let Ok(value) = ctx
            .journal_mut()
            .db_mut()
            .load_storage(address, &field, &indices)
        else {
            return fatal("failed to read value");
        };
        value.clone()
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
            } else if let Some(value) = &stored_value {
                let Ok(value) = serde_json::from_slice::<String>(value) else {
                    return fatal("failed to parse raw value");
                };
                let Ok(value) = value.parse::<$ty>() else {
                    return fatal("failed to parse value");
                };
                value.abi_encode()
            } else {
                vec![]
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
            } else if let Some(value) = &stored_value {
                let Ok(value) = serde_json::from_slice::<String>(value) else {
                    return fatal("failed to parse raw value");
                };
                value.abi_encode()
            } else {
                vec![]
            }
        }
        ScillaType::Map(_, _) => unreachable!("map will not be returned from `get_indices`"),
    };

    Ok(PrecompileOutput::new(required_gas, value.into(), 0))
}

fn field_type(
    code: &Code,
    address: Address,
    field: &str,
) -> std::result::Result<(String, Option<serde_json::Value>), PrecompileErrors> {
    let Code::Scilla {
        types, init_data, ..
    } = code
    else {
        return err(format!("{address} is not a scilla contract"));
    };

    match (init_data.iter().find(|p| p.name == field), types.get(field)) {
        (_, Some((ty, _))) => Ok((ty.clone(), None)),
        (Some(v), None) => Ok((v.ty.clone(), Some(v.value.clone()))),
        (None, None) => err(format!("variable {field} does not exist in contract")),
    }
}
