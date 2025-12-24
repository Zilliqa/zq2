#![allow(clippy::all)]
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/zilliqa_message.rs"));

impl From<Vec<u8>> for ByteArray {
    fn from(data: Vec<u8>) -> Self {
        ByteArray { data }
    }
}

impl From<Box<[u8]>> for ByteArray {
    fn from(data: Box<[u8]>) -> Self {
        ByteArray { data: data.into() }
    }
}
