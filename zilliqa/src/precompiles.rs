use std::sync::Arc;

use blsful::Bls12381G2Impl;
use ethabi::{decode, encode, short_signature, ParamType, Token};
use revm::{
    precompile::PrecompileError,
    primitives::{
        alloy_primitives::private::alloy_rlp::Encodable, Address, Bytes, PrecompileErrors,
        PrecompileOutput, PrecompileResult,
    },
    ContextPrecompile, ContextStatefulPrecompile, InnerEvmContext,
};

use crate::state::State;

pub(crate) fn get_custom_precompiles<'a>() -> Vec<(Address, ContextPrecompile<&'a State>)> {
    vec![
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL"),
            ContextPrecompile::ContextStateful(Arc::new(ERC20Precompile)),
        ),
        (
            Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0PPV"),
            ContextPrecompile::ContextStateful(Arc::new(PopVerifyPrecompile)),
        ),
    ]
}

pub(crate) struct ERC20Precompile;

impl ERC20Precompile {
    fn get_balance(
        input: &[u8],
        _gas_price: u64,
        context: &mut InnerEvmContext<&State>,
    ) -> PrecompileResult {
        let Ok(decoded) = decode(&[ParamType::Address], input) else {
            return Err(
                PrecompileError::Other("Unable to decode provided account address".into()).into(),
            );
        };

        if decoded.is_empty() {
            return Err(
                PrecompileError::Other("Decoded token vector has zero length!".into()).into(),
            );
        }

        let Token::Address(address) = decoded[0] else {
            return Err(PrecompileError::Other(
                "Decoded value is not a proper address type!".into(),
            )
            .into());
        };
        let address = Address::new(address.0);

        let Ok(account) = context.db.get_account(address) else {
            return Ok(PrecompileOutput::new(
                0,
                encode(&[Token::Uint(ethabi::Uint::from(0))]).into(),
            ));
        };

        let balance = ethabi::Uint::from(account.balance);
        let output = encode(&[Token::Uint(balance)]);

        // Don't charge gas
        Ok(PrecompileOutput::new(0, output.into()))
    }
}

impl ContextStatefulPrecompile<&State> for ERC20Precompile {
    fn call(
        &self,
        input: &Bytes,
        gas_price: u64,
        context: &mut InnerEvmContext<&State>,
    ) -> PrecompileResult {
        if input.length() < 4 {
            return Err(PrecompileError::Other(
                "Provided input must be at least 4-byte long".into(),
            )
            .into());
        }

        let dispatch_table: [([u8; 4], _); 1] = [(
            short_signature("balanceOf", &[ParamType::Address]),
            Self::get_balance,
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

pub(crate) struct PopVerifyPrecompile;

// keep in-sync with zilliqa/src/contracts/deposit.sol
impl PopVerifyPrecompile {
    const POP_VERIFY_GAS_PRICE: u64 = 1_000_000u64; // FIXME: Gas Price?
    fn pop_verify(
        input: &[u8],
        gas_limit: u64,
        _context: &mut InnerEvmContext<&State>,
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

impl ContextStatefulPrecompile<&State> for PopVerifyPrecompile {
    fn call(
        &self,
        input: &Bytes,
        gas_price: u64,
        context: &mut InnerEvmContext<&State>,
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
