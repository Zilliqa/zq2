use alloy::primitives::Address;
use blsful::Bls12381G2Impl;
use ethabi::{ParamType, Token, decode, encode, short_signature};
use revm::{
    precompile::PrecompileError,
    primitives::{
        Bytes,
        alloy_primitives::private::alloy_rlp::Encodable,
    },
};
use revm::interpreter::InputsImpl;
use revm_precompile::{PrecompileOutput, PrecompileResult};
use crate::exec::{ZQ2EvmContext};
use crate::precompiles::ContextPrecompile;

pub struct PopVerify;

// keep in-sync with zilliqa/src/contracts/deposit_v2.sol
impl<I> PopVerify {
    const POP_VERIFY_GAS_PRICE: u64 = 1_000_000u64; // FIXME: Gas Price?
    fn pop_verify(
        input: &[u8],
        gas_limit: u64,
        _: &mut ZQ2EvmContext<I>,
    ) -> PrecompileResult {
        if gas_limit < Self::POP_VERIFY_GAS_PRICE {
            return Err(PrecompileError::OutOfGas);
        }

        let Ok(decoded) = decode(&[ParamType::Bytes, ParamType::Bytes], input) else {
            return Err(PrecompileError::Other("ABI input decoding error!".into()).into());
        };
        if decoded.len() != 2 {
            // expected 2 arguments
            return Err(PrecompileError::Other("ABI inputs missing".into()).into());
        };

        let Ok(pop) = blsful::ProofOfPossession::<Bls12381G2Impl>::try_from(
            decoded[0].to_owned().into_bytes().unwrap(),
        ) else {
            return Err(PrecompileError::Other("ABI signature invalid".into()).into());
        };

        let Ok(pk) = blsful::PublicKey::<Bls12381G2Impl>::try_from(
            decoded[1].to_owned().into_bytes().unwrap(),
        ) else {
            return Err(PrecompileError::Other("ABI pubkey invalid".into()).into());
        };

        let result = pop.verify(pk).is_ok();

        // FIXME: Gas?
        let output = encode(&[Token::Bool(result)]);
        Ok(PrecompileOutput::new(
            Self::POP_VERIFY_GAS_PRICE,
            output.into(),
        ))
    }
}

impl<I> ContextPrecompile<ZQ2EvmContext<'_, I>> for PopVerify {
    fn call(
        &self,
        ctx: &mut ZQ2EvmContext<I>,
        _dest: Address,
        input: &InputsImpl,
        _is_static: bool,
        gas_limit: u64
    ) -> PrecompileResult {
        if input.length() < 4 {
            return Err(PrecompileError::Other(
                "Provided input must be at least 4-byte long".into(),
            )
            .into());
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
            return Err(PrecompileError::Other(
                "Unable to find handler with given selector".to_string(),
            )
            .into());
        };

        handler.1(&raw_input[4..], gas_limit, ctx)
    }
}
