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

pub struct PopVerify;

/// A custom Proof of Possession in which the bls public key, an evm address and a chain_id are signed over
// keep in-sync with zilliqa/src/contracts/deposit.sol
impl PopVerify {
    const POP_VERIFY_GAS_PRICE: u64 = 1_000_000u64; // FIXME: Gas Price?
    fn pop_verify(
        input: &[u8],
        gas_limit: u64,
        _context: &mut InnerEvmContext<PendingState>,
    ) -> PrecompileResult {
        if gas_limit < Self::POP_VERIFY_GAS_PRICE {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let Ok(decoded) = decode(&[ParamType::Bytes, ParamType::Bytes], input) else {
            return Err(PrecompileError::Other("ABI input decoding error!".into()).into());
        };
        if decoded.len() != 2 {
            // expected 2 arguments
            return Err(PrecompileError::Other("ABI inputs missing".into()).into());
        };

        let Ok(pop) = <blsful::Bls12381G2Impl as blsful::Pairing>::Signature::try_from(
            decoded[0].to_owned().into_bytes().unwrap(),
        ) else {
            return Err(PrecompileError::Other("ABI signature invalid".into()).into());
        };

        let Ok(pk) = blsful::PublicKey::<Bls12381G2Impl>::try_from(
            decoded[1].to_owned().into_bytes().unwrap(),
        ) else {
            return Err(PrecompileError::Other("ABI pubkey invalid".into()).into());
        };

        // message which pop signs over
        let mut pop_message = [0u8; 98];
        pop_message[..48].copy_from_slice(&pk.0.to_compressed());
        pop_message[48..56].copy_from_slice(&_context.env.cfg.chain_id.to_le_bytes());
        pop_message[56..].copy_from_slice(
            &_context
                .env
                .tx
                .caller
                .to_checksum_buffer(Some(_context.env.cfg.chain_id))
                .into_inner(),
        );

        let result = blsful::Signature::Basic(pop)
            .verify(&pk, pop_message)
            .is_ok();

        // FIXME: Gas?
        let output = encode(&[Token::Bool(result)]);
        Ok(PrecompileOutput::new(
            Self::POP_VERIFY_GAS_PRICE,
            output.into(),
        ))
    }
}

impl ContextStatefulPrecompile<PendingState> for PopVerify {
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
            short_signature("popVerify", &[ParamType::Bytes, ParamType::Bytes]),
            Self::pop_verify,
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
