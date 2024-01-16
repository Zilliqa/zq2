use core::fmt;

// Convenience function to print long vectors, truncating if they are massive
pub fn sshortened_vec(val: &Vec<u8>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", vec_tos_string_concat(val))
}

fn vec_tos_string_concat<T: fmt::Debug + fmt::Display + std::fmt::LowerHex>(
    input: &Vec<T>,
) -> String {
    if input.len() > 64 {
        let start = &input[0..5];
        let end = &input[input.len() - 5..];
        let start_str = start
            .iter()
            .map(|x| format!("{:#02x}", x))
            .collect::<Vec<_>>()
            .join(", ");
        let end_str = end
            .iter()
            .map(|x| format!("{:#02x}", x))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{}, ..., {}]", start_str, end_str)
    } else {
        format!("{:?}", input)
    }
}
