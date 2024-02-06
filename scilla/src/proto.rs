use prost::Message;

#[derive(Clone, PartialEq, Eq, Message)]
pub struct ProtoScillaVal {
    #[prost(oneof = "proto_scilla_val::ValType", tags = "1, 2")]
    pub val_type: Option<proto_scilla_val::ValType>,
}

/// Nested message and enum types in `ProtoScillaVal`.
pub mod proto_scilla_val {
    use std::collections::HashMap;

    use prost::{Message, Oneof};

    #[derive(Clone, PartialEq, Eq, Message)]
    pub struct Map {
        #[prost(map = "string, message", tag = "1")]
        pub m: HashMap<String, super::ProtoScillaVal>,
    }

    #[derive(Clone, PartialEq, Eq, Oneof)]
    pub enum ValType {
        #[prost(bytes, tag = "1")]
        Bval(Vec<u8>),
        #[prost(message, tag = "2")]
        Mval(Map),
    }
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct ProtoScillaQuery {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(uint32, tag = "2")]
    pub mapdepth: u32,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub indices: Vec<Vec<u8>>,
    #[prost(bool, tag = "4")]
    pub ignoreval: bool,
}
