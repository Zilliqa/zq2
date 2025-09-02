use alloy::primitives::Address;
use blsful::Bls12381G2Impl;
use ethabi::{ParamType, Token, decode, encode, short_signature};
use revm::{
    interpreter::{
        Gas, InputsImpl, InstructionResult, InterpreterResult, interpreter::EthInterpreter,
    },
    precompile::{PrecompileError, PrecompileOutput, PrecompileResult},
};
use revm_inspector::Inspector;

use crate::{evm::ZQ2EvmContext, inspector::ScillaInspector, precompiles::ContextPrecompile};

pub struct BlsVerify;

// keep in-sync with zilliqa/src/contracts/deposit_v3.sol
impl BlsVerify {
    /// We charge gas as if we were using Ethereum precompile gas prices for each operation:
    ///     - Message to hash: SHA256 over 76 byte message: 60 + 12 * 3 = 96
    ///     - Hash to point: Rough estimate                             = 100_000
    ///     - Single pairing check on BLS12-381 (ref: EIP-1108)         = 79_000
    ///                                                                 = 180_000
    const BLS_VERIFY_GAS_PRICE: u64 = 180_000u64;
    fn bls_verify(
        input: &[u8],
        gas_limit: u64,
        _: &mut ZQ2EvmContext,
    ) -> Result<Option<InterpreterResult>, String> {
        if gas_limit < Self::BLS_VERIFY_GAS_PRICE {
            return Err(PrecompileError::OutOfGas.to_string());
        }

        let Ok(decoded) = decode(
            &[ParamType::Bytes, ParamType::Bytes, ParamType::Bytes],
            input,
        ) else {
            return Err("ABI input decoding error!".into());
        };
        if decoded.len() != 3 {
            // expected 3 arguments
            return Err("ABI inputs missing".into());
        };

        let message = decoded[0].to_owned().into_bytes().unwrap();

        let Ok(signature) = <blsful::Bls12381G2Impl as blsful::Pairing>::Signature::try_from(
            decoded[1].to_owned().into_bytes().unwrap(),
        ) else {
            return Err("ABI signature invalid".into());
        };

        let Ok(pk) = blsful::PublicKey::<Bls12381G2Impl>::try_from(
            decoded[2].to_owned().into_bytes().unwrap(),
        ) else {
            return Err("ABI pubkey invalid".into());
        };

        let result = blsful::Signature::Basic(signature)
            .verify(&pk, message)
            .is_ok();

        // FIXME: Gas?
        let output = encode(&[Token::Bool(result)]);
        Ok(Some(InterpreterResult::new(
            InstructionResult::default(),
            output.into(),
            Gas::new_spent(Self::BLS_VERIFY_GAS_PRICE),
        )))
    }
}

impl ContextPrecompile for BlsVerify {
    fn call(
        &self,
        ctx: &mut ZQ2EvmContext,
        _target: Address,
        input: &InputsImpl,
        _is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<InterpreterResult>, String> {
        if input.input.len() < 4 {
            return Err("Provided input must be at least 4-byte long".into());
        }

        let dispatch_table: [([u8; 4], _); 1] = [(
            short_signature(
                "blsVerify",
                &[ParamType::Bytes, ParamType::Bytes, ParamType::Bytes],
            ),
            Self::bls_verify,
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
