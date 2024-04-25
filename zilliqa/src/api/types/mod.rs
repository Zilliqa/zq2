use serde::{ser::SerializeSeq, Serializer};

use super::to_hex::ToHex;

pub mod eth;
pub mod ots;
pub mod zil;

pub fn hex<S: Serializer, T: ToHex>(data: T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&data.to_hex())
}

pub fn option_hex<S: Serializer, T: ToHex>(
    data: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if let Some(data) = data {
        serializer.serialize_some(&data.to_hex())
    } else {
        serializer.serialize_none()
    }
}

pub fn vec_hex<S: Serializer, T: ToHex>(data: &[T], serializer: S) -> Result<S::Ok, S::Error> {
    let mut serializer = serializer.serialize_seq(Some(data.len()))?;

    data.iter()
        .try_for_each(|item| serializer.serialize_element(&item.to_hex()))?;

    serializer.end()
}

pub fn bool_as_int<S: Serializer>(b: &bool, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(if *b { "0x1" } else { "0x0" })
}

pub fn hex_no_prefix<S: Serializer, T: ToHex>(data: T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&data.to_hex_no_prefix())
}

pub fn option_hex_no_prefix<S: Serializer, T: ToHex>(
    data: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if let Some(data) = data {
        serializer.serialize_some(&data.to_hex_no_prefix())
    } else {
        serializer.serialize_none()
    }
}
