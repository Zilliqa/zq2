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
    let payload = encoded[4..];

    let Some(vec) = (match encoded[0..4] {
        REVERT_SELECTOR => {
            let input_type = [ParamType::String];
            ethabi::decode(&input_type, &payload)
        }
        PANIC_SELECTOR => {
            let input_type = [ParamType::Uint(256)];
            ethabi::decode(&input_type, &payload)
        }
        _ => {
            return generic_error;
        }
    }) else {
        return generic_error;
    };

    let Some(token) = vec.get(0) else {
        return generic_error;
    };

    return match token {
        Token::String(value) => generic_error + ": " + value,
        Token::Uint(value) => {
            format!("{}: Panic due to: {}", generic_error, value)
        }
        _ => generic_error,
    };
}
