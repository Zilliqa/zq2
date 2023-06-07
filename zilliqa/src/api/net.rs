use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use cita_trie::DB;
use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

pub fn rpc_module<D: DB>(node: Arc<Mutex<Node<D>>>) -> RpcModule<Arc<Mutex<Node<D>>>> {
    super::declare_module!(node, D, [("net_version", NetRpc::version)])
}

struct NetRpc<'a, D: DB> {
    phantom_db: PhantomData<&'a D>,
}
impl<D: DB> NetRpc<'_, D> {
    fn version(_: Params, node: &Arc<Mutex<Node<D>>>) -> Result<String> {
        Ok(node.lock().unwrap().config.eth_chain_id.to_string())
    }
}
