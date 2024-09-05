use ethabi::{decode, encode, short_signature, ParamType, Token};
use revm::{
    precompile::PrecompileError,
    primitives::{
        alloy_primitives::private::alloy_rlp::Encodable, Address, Bytes, PrecompileOutput,
        PrecompileResult,
    },
    ContextStatefulPrecompile, InnerEvmContext,
};

use crate::exec::PendingState;

pub struct ERC20Precompile;

impl ERC20Precompile {
    fn get_balance(
        input: &[u8],
        _gas_price: u64,
        context: &mut InnerEvmContext<PendingState>,
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

        let Ok(account) = context.db.pre_state.get_account(address) else {
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

impl ContextStatefulPrecompile<PendingState> for ERC20Precompile {
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
