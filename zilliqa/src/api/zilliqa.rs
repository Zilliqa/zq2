//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use anyhow::anyhow;
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use cita_trie::DB;
use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

pub fn rpc_module<D: DB>(node: Arc<Mutex<Node<D>>>) -> RpcModule<Arc<Mutex<Node<D>>>> {
    super::declare_module!(
        node,
        D,
        [
            ("GetCurrentMiniEpoch", ZilliqaRpc::get_current_mini_epoch),
            ("GetVersion", ZilliqaRpc::get_git_commit),
        ]
    )
}

struct ZilliqaRpc<'a, D: DB> {
    phantom_db: PhantomData<&'a D>,
}
impl<D: DB> ZilliqaRpc<'_, D> {
    fn get_current_mini_epoch(_: Params, node: &Arc<Mutex<Node<D>>>) -> Result<String> {
        Ok(node.lock().unwrap().view().to_string())
    }
    fn get_git_commit(_: Params, _: &Arc<Mutex<Node<D>>>) -> Result<String> {
        Ok(env!("VERGEN_GIT_DESCRIBE").to_string())
    }
}
