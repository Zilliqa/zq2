use crate::{node::Node, uccb::validator_node};
use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{error, info, warn};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let module = super::declare_module!(node, [("uccb_validators", validators),],);

    module
}

fn validators(_: Params, node: &Arc<Mutex<Node>>) -> Result<&'static str> {
    //expect_end_of_params(&mut params.sequence(), 0, 0)?;
    let uccb_state_info = node.lock().unwrap().uccb_state_info();
    Ok("Ok")
}
