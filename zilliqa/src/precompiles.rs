use crate::state::State;
use ethabi::{encode, ParamType, Token};
use std::sync::Arc;

use revm::precompile::PrecompileError;
use revm::primitives::alloy_primitives::private::alloy_rlp::Encodable;
use revm::{
    primitives::{Address, Bytes, PrecompileResult},
    ContextPrecompile, ContextStatefulPrecompile, InnerEvmContext,
};
use sha3::{Digest, Keccak256};

pub(crate) fn get_custom_precompiles<'a>() -> Vec<(Address, ContextPrecompile<&'a State>)> {
    vec![(
        Address::from(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL"),
        ContextPrecompile::ContextStateful(Arc::new(ERC20Precompile)),
    )]
}

pub(crate) struct ERC20Precompile;

impl ERC20Precompile {
    fn get_balance(
        input: &[u8],
        _gas_price: u64,
        context: &mut InnerEvmContext<&State>,
    ) -> PrecompileResult {
        let Ok(decoded) = ethabi::decode(&[ParamType::Address], input) else {
            return Err(PrecompileError::Other(
                "Unable to decode provided account address".into(),
            ));
        };

        if decoded.is_empty() {
            return Err(PrecompileError::Other(
                "Decoded token vector has zero length!".into(),
            ));
        }

        let Token::Address(address) = decoded[0] else {
            return Err(PrecompileError::Other(
                "Decoded value is not a proper address type!".into(),
            ));
        };

        let Ok(account) = context.db.get_account(address) else {
            return Err(PrecompileError::Other(
                "Unable to get account with given address".into(),
            ));
        };

        let balance = primitive_types::U256::from(account.balance);
        let output = encode(&[Token::Uint(balance)]);

        // Don't charge gas
        Ok((0u64, output.into()))
    }
}

fn make_selector(signature: &str) -> [u8; 4] {
    let signature = Keccak256::digest(signature).to_vec();
    let slice = signature.as_slice();
    let res: [u8; 4] = slice[..4].try_into().unwrap();
    res
}

impl ContextStatefulPrecompile<&State> for ERC20Precompile {
    fn call(
        &self,
        _input: &Bytes,
        _gas_price: u64,
        _context: &mut InnerEvmContext<&State>,
    ) -> PrecompileResult {
        if _input.length() < 4 {
            return Err(PrecompileError::Other(
                "Provided input must be at least 4-byte long".into(),
            ));
        }

        let dispatch_table: [([u8; 4], _); 1] =
            [(make_selector("balanceOf(address)"), Self::get_balance)];

        let Some(handler) = dispatch_table
            .iter()
            .find(|&predicate| predicate.0 == _input[..4])
        else {
            return Err(PrecompileError::Other(
                "Unable to find handler with given selector".to_string(),
            ));
        };

        handler.1(&_input[4..], _gas_price, _context)
    }
}
