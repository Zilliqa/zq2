use cita_trie::DB;
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use super::*;
use anyhow::Result;

use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

use super::types::EthBlock;

pub fn rpc_module<D: DB>(node: Arc<Mutex<Node<D>>>) -> RpcModule<Arc<Mutex<Node<D>>>> {
    super::declare_module!(
        node,
        D,
        [("erigon_getHeaderByNumber", ErigonRpc::get_header_by_number)]
    )
}

struct ErigonRpc<'a, D: DB> {
    phantom_db: PhantomData<&'a D>,
}

impl<D: DB> ErigonRpc<'_, D> {
    fn get_header_by_number(
        params: Params,
        node: &Arc<Mutex<Node<D>>>,
    ) -> Result<Option<EthBlock>> {
        let block: u64 = params.one()?;

        // Erigon headers are a subset of the full block response. We choose to just return the full block.
        let header = node
            .lock()
            .unwrap()
            .get_block_by_view(block)
            .map(EthBlock::from);

        Ok(header)
    }
}
