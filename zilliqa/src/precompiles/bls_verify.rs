use blsful::Bls12381G2Impl;
use ethabi::{decode, encode, short_signature, ParamType, Token};
use revm::{
    precompile::PrecompileError,
    primitives::{
        alloy_primitives::private::alloy_rlp::Encodable, Bytes, PrecompileErrors, PrecompileOutput,
        PrecompileResult,
    },
    ContextStatefulPrecompile, InnerEvmContext,
};

use crate::exec::PendingState;

pub struct BlsVerify;

// keep in-sync with zilliqa/src/contracts/deposit_v3.sol
impl BlsVerify {
    const BLS_VERIFY_GAS_PRICE: u64 = 1_000_000u64; // FIXME: Gas Price?
    fn bls_verify(
        input: &[u8],
        gas_limit: u64,
        _context: &mut InnerEvmContext<PendingState>,
    ) -> PrecompileResult {
        if gas_limit < Self::BLS_VERIFY_GAS_PRICE {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let Ok(decoded) = decode(
            &[ParamType::Bytes, ParamType::Bytes, ParamType::Bytes],
            input,
        ) else {
            return Err(PrecompileError::Other("ABI input decoding error!".into()).into());
        };
        if decoded.len() != 3 {
            // expected 3 arguments
            return Err(PrecompileError::Other("ABI inputs missing".into()).into());
        };

        let message = decoded[0].to_owned().into_bytes().unwrap();

        let Ok(signature) = <blsful::Bls12381G2Impl as blsful::Pairing>::Signature::try_from(
            decoded[1].to_owned().into_bytes().unwrap(),
        ) else {
            return Err(PrecompileError::Other("ABI signature invalid".into()).into());
        };

        let Ok(pk) = blsful::PublicKey::<Bls12381G2Impl>::try_from(
            decoded[2].to_owned().into_bytes().unwrap(),
        ) else {
            return Err(PrecompileError::Other("ABI pubkey invalid".into()).into());
        };

        let result = blsful::Signature::Basic(signature)
            .verify(&pk, message)
            .is_ok();

        // FIXME: Gas?
        let output = encode(&[Token::Bool(result)]);
        Ok(PrecompileOutput::new(
            Self::BLS_VERIFY_GAS_PRICE,
            output.into(),
        ))
    }
}

impl ContextStatefulPrecompile<PendingState> for BlsVerify {
    fn call(
        &self,
        input: &Bytes,
        gas_price: u64,
        context: &mut InnerEvmContext<PendingState>,
    ) -> PrecompileResult {
        if input.length() < 4 {
            return Err(PrecompileError::Other(
                "Provided input must be at least 4-byte long".into(),
            )
            .into());
        }

        let dispatch_table: [([u8; 4], _); 1] = [(
            short_signature(
                "blsVerify",
                &[ParamType::Bytes, ParamType::Bytes, ParamType::Bytes],
            ),
            Self::bls_verify,
        )];

        let Some(handler) = dispatch_table
            .iter()
            .find(|&predicate| predicate.0 == input[..4])
        else {
            return Err(PrecompileError::Other(
                "Unable to find handler with given selector".to_string(),
            )
            .into());
        };

        handler.1(&input[4..], gas_price, context)
    }
}
