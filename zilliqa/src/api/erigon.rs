use std::{panic::AssertUnwindSafe, sync::Arc};
use tokio::sync::Mutex;

use anyhow::Result;
use jsonrpsee::types::Params;
use jsonrpsee::RpcModule;

use crate::node::Node;

use super::types::EthBlock;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("erigon_getHeaderByNumber", get_header_by_number)])
}

async fn get_header_by_number(
    params: Params<'_>,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<EthBlock>> {
    let block: u64 = params.one()?;

    // Erigon headers are a subset of the full block response. We choose to just return the full block.
    let header = node
        .lock()
        .await
        .get_block_by_view(block)
        .await?
        .as_ref()
        .map(EthBlock::from);

    Ok(header)
}
