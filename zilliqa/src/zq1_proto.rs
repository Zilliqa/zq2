#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ByteArray {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

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

#[derive(Clone, PartialEq, prost::Message)]
pub struct ProtoTransactionCoreInfo {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub toaddr: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub senderpubkey: Option<ByteArray>,
    #[prost(message, optional, tag = "5")]
    pub amount: Option<ByteArray>,
    #[prost(message, optional, tag = "6")]
    pub gasprice: Option<ByteArray>,
    #[prost(uint64, tag = "7")]
    pub gaslimit: u64,
    #[prost(oneof = "Nonce", tags = "2")]
    pub oneof2: Option<Nonce>,
    #[prost(oneof = "Code", tags = "8")]
    pub oneof8: Option<Code>,
    #[prost(oneof = "Data", tags = "9")]
    pub oneof9: Option<Data>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Nonce {
    #[prost(uint64, tag = "2")]
    Nonce(u64),
}
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Code {
    #[prost(bytes, tag = "8")]
    Code(Vec<u8>),
}
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Data {
    #[prost(bytes, tag = "9")]
    Data(Vec<u8>),
}
