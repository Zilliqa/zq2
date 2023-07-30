use primitive_types::{H160, H256, U256};
use protobuf::Message;
use std::fmt::Write;

use crate::protos::{Evm as EvmProto, ScillaMessage};

pub fn log_evm_result(result: &EvmProto::EvmResult) -> String {
    format!("{:?}", result)
}
