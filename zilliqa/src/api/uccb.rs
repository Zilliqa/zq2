use crate::node::Node;
use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use std::sync::{Arc, Mutex};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let module = super::declare_module!(
        node,
        [
            ("uccb_relayed_events", relayed_events),
            ("uccb_pending_relayed_events", pending_relayed_events),
        ],
    );

    module
}

fn relayed_events(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    if let Ok(uccb_state_info) = node.lock().unwrap().uccb_state_info().lock() {
        Ok(serde_json::to_string(&uccb_state_info.relayed_events)?)
    } else {
        Err(anyhow!("failed"))
    }
}

fn pending_relayed_events(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    if let Ok(uccb_state_info) = node.lock().unwrap().uccb_state_info().lock() {
        Ok(serde_json::to_string(
            &uccb_state_info.pending_relayed_events,
        )?)
    } else {
        Err(anyhow!("failed"))
    }
}
