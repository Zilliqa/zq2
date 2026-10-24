use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    crypto::Hash,
    serde_util::{bool_as_str, num_as_str},
    transaction::{ScillaGas, ZilAmount},
};

#[derive(Debug, Deserialize)]
pub struct CheckOutput {
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
    pub contract_info: Option<ContractInfo>,
}

#[derive(Debug, Deserialize)]
pub struct Error {
    pub start_location: Location,
    pub error_message: String,
}

#[derive(Debug, Deserialize)]
pub struct Location {
    pub line: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct ContractInfo {
    pub scilla_major_version: String,
    pub fields: Vec<Param>,
    pub transitions: Vec<Transition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Transition {
    #[serde(rename = "vname")]
    pub name: String,
    pub params: Vec<TransitionParam>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TransitionParam {
    #[serde(rename = "vname")]
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Param {
    #[serde(rename = "vname")]
    pub name: String,
    pub depth: u64,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateOutput {
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub errors: Vec<Error>,
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
}

#[derive(Debug, Deserialize)]
pub struct InvokeOutput {
    #[serde(rename = "_accepted", with = "bool_as_str")]
    pub accepted: bool,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub events: Vec<ScillaEvent>,
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
}

#[derive(Debug, Deserialize)]
pub struct ScillaEvent {
    #[serde(rename = "_eventname")]
    pub event_name: String,
    pub params: Vec<ParamValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ParamValue {
    #[serde(rename = "vname")]
    pub name: String,
    pub value: Value,
    #[serde(rename = "type")]
    pub ty: String,
}

impl ParamValue {
    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.ty.as_bytes())
            .with(self.value.to_string().as_bytes())
            .with(self.name.as_bytes())
            .finalize()
    }
}

#[derive(Debug, Deserialize)]
pub struct Message {
    #[serde(rename = "_tag")]
    pub tag: String,
    #[serde(rename = "_amount", with = "num_as_str")]
    pub amount: ZilAmount,
    #[serde(rename = "_recipient")]
    pub recipient: Address,
    pub params: Value,
}
