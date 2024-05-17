use ethabi::{ParamType, Token};

pub(crate) fn extract_revert_msg(encoded: &[u8]) -> String {
    // It could be either REVERT = keccka256("Error(string)") or PANIC = keccka256("Panic(uint256)")
    // See https://docs.soliditylang.org/en/latest/control-structures.html#revert

    // Try to decode revert message provided by EVM
    const REVERT_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
    const PANIC_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

    let generic_error = String::from("execution reverted");
    // At least 4 elemenets + anything to decode
    if encoded.len() < REVERT_SELECTOR.len() + 1 {
        return generic_error;
    }

    let payload = &encoded[4..];

    let vec = if encoded.starts_with(&REVERT_SELECTOR) {
        let input_type = [ParamType::String];
        ethabi::decode(&input_type, payload)
    } else if encoded.starts_with(&PANIC_SELECTOR) {
        let input_type = [ParamType::Uint(256)];
        ethabi::decode(&input_type, payload)
    } else {
        return generic_error;
    };

    let Ok(vec) = vec else {
        return generic_error;
    };

    let Some(token) = vec.first() else {
        return generic_error;
    };

    match token {
        Token::String(value) => generic_error + ": " + value,
        Token::Uint(value) => {
            format!("{}: panic due to: {}", generic_error, value)
        }
        _ => generic_error,
    }
}

#[cfg(test)]
mod tests {
    use crate::eth_helpers::extract_revert_msg;

    #[test]
    fn revert() {
        // Based on https://github.com/ethereum/go-ethereum/blob/master/accounts/abi/abi_test.go#L1187
        let cases = [
            ("", "execution reverted"),
            ("08c379a1", "execution reverted"),
            ("08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d72657665727420726561736f6e00000000000000000000000000000000000000", "execution reverted: revert reason"),
            ("4e487b710000000000000000000000000000000000000000000000000000000000000000", "execution reverted: panic due to: 0"),
        ];
        for (input, expected) in cases {
            let as_bytes = hex::decode(input).unwrap();
            assert_eq!(extract_revert_msg(&as_bytes), expected.to_string());
        }
    }
}
