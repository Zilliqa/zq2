use super::*;
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use cita_trie::DB;
use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

pub fn rpc_module<D: DB>(node: Arc<Mutex<Node<D>>>) -> RpcModule<Arc<Mutex<Node<D>>>> {
    super::declare_module!(node, D, [("web3_clientVersion", Web3Rpc::client_version)])
}

struct Web3Rpc<'a, D: DB> {
    phantom_db: PhantomData<&'a D>,
}
impl<D: DB> Web3Rpc<'_, D> {
    fn client_version(_: Params, _: &Arc<Mutex<Node<D>>>) -> Result<&'static str> {
        // Format: "<name>/<version>"
        Ok(concat!("zilliqa2/v", env!("CARGO_PKG_VERSION")))
    }
}
