pub mod get_header_by_number;

use crate::node::Node;
use jsonrpsee::RpcModule;
use std::sync::{Arc, Mutex};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [(
            "erigon_getHeaderByNumber",
            get_header_by_number::get_header_by_number
        )]
    )
}
