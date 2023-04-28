//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::sync::{Arc, Mutex};

use jsonrpsee::RpcModule;

use crate::node::Node;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let mut module = RpcModule::new(node);

    module
        .register_method("GetCurrentMiniEpoch", |_, node| {
            node.lock().unwrap().view().to_string()
        })
        .unwrap();

    module
}
