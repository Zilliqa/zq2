use alloy::primitives::Address;
use blsful::Bls12381G2Impl;
use ethabi::{ParamType, Token, decode, encode, short_signature};
use revm::{
    interpreter::{Gas, InputsImpl, InstructionResult, InterpreterResult},
    precompile::PrecompileError,
};

use crate::{evm::ZQ2EvmContext, precompiles::ContextPrecompile};

pub struct PopVerify;

// keep in-sync with zilliqa/src/contracts/deposit_v2.sol
impl PopVerify {
    const POP_VERIFY_GAS_PRICE: u64 = 1_000_000u64; // FIXME: Gas Price?
    fn pop_verify(
        input: &[u8],
        gas_limit: u64,
        _: &mut ZQ2EvmContext,
    ) -> Result<Option<InterpreterResult>, String> {
        let mut gas_tracker = Gas::new(gas_limit);

        if !gas_tracker.record_cost(Self::POP_VERIFY_GAS_PRICE) {
            return Err(PrecompileError::OutOfGas.to_string());
        }

        let Ok(decoded) = decode(&[ParamType::Bytes, ParamType::Bytes], input) else {
            return Err("ABI input decoding error!".into());
        };
        if decoded.len() != 2 {
            // expected 2 arguments
            return Err("ABI inputs missing".into());
        };

        let Ok(pop) = blsful::ProofOfPossession::<Bls12381G2Impl>::try_from(
            decoded[0].to_owned().into_bytes().unwrap(),
        ) else {
            return Err("ABI signature invalid".into());
        };

        let Ok(pk) = blsful::PublicKey::<Bls12381G2Impl>::try_from(
            decoded[1].to_owned().into_bytes().unwrap(),
        ) else {
            return Err("ABI pubkey invalid".into());
        };

        let result = pop.verify(pk).is_ok();

        let output = encode(&[Token::Bool(result)]);
        Ok(Some(InterpreterResult::new(
            InstructionResult::default(),
            output.into(),
            gas_tracker,
        )))
    }
}

impl ContextPrecompile for PopVerify {
    fn call(
        &self,
        ctx: &mut ZQ2EvmContext,
        _dest: Address,
        input: &InputsImpl,
        _is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<InterpreterResult>, String> {
        if input.input.len() < 4 {
            return Err("Provided input must be at least 4-byte long".into());
        }

        let dispatch_table: [([u8; 4], _); 1] = [(
            short_signature("popVerify", &[ParamType::Bytes, ParamType::Bytes]),
            Self::pop_verify,
        )];

        let raw_input = input.input.bytes(ctx);
        let Some(handler) = dispatch_table
            .iter()
            .find(|&predicate| predicate.0 == raw_input[..4])
        else {
            return Err("Unable to find handler with given selector".into());
        };

        handler.1(&raw_input[4..], gas_limit, ctx)
    }
}
