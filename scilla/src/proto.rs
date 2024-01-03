#![allow(clippy::all)]
include!(concat!(env!("OUT_DIR"), "/zilliqa_message.rs"));
include!(concat!(env!("OUT_DIR"), "/scilla_message.rs"));

impl<T: Into<Vec<u8>>> From<T> for ByteArray {
    fn from(data: T) -> Self {
        ByteArray { data: data.into() }
    }
}
