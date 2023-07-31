use crate::protos::evm as EvmProto;

pub fn log_evm_result(result: &EvmProto::EvmResult) -> String {
    format!("{:?}", result)
}
