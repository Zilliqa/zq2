use primitive_types::{H256, H160};
use serde::Deserialize;
use serde::Serialize;
use jsonrpc_core::Params;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Account {
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage_root: Option<H256>,
    pub is_scilla: bool,
}

/// Response from the 'check' command
#[derive(Deserialize, Debug)]
pub struct CheckOutput {
    pub contract_info: ContractInfo,
}

#[derive(Deserialize, Debug)]
pub struct ContractInfo {
    pub scilla_major_version: String,
    pub fields: Vec<Param>,
}

#[derive(Deserialize, Debug)]
pub struct Param {
    #[serde(rename = "vname")]
    pub name: String,
    pub depth: u64,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Params,
    pub id: u32,
}

impl JsonRpcRequest {
    pub fn new(method: &str, params: Params, id: u32) -> Self {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id,
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcError {
    code: i32,
    message: String,
    data: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct InvokeOutput {
    #[serde(rename = "_accepted", with = "str_bool")]
    pub accepted: bool,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub events: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    #[serde(rename = "_tag")]
    pub tag: String,
    #[serde(rename = "_amount")]
    pub amount: String,
    #[serde(rename = "_recipient")]
    pub recipient: H160,
    pub params: Value,
}

mod str_bool {
    use serde::{
        de::{self, Unexpected},
        Deserialize, Deserializer,
    };

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
        let s = String::deserialize(d)?;
        let b = s
            .parse()
            .map_err(|_| de::Error::invalid_value(Unexpected::Str(&s), &"a boolean"))?;
        Ok(b)
    }
}
