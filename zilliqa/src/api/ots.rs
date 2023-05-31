use std::sync::{Arc, Mutex};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::H256;

use crate::{crypto::Hash, node::Node};

use super::types::OtterscanBlockDetails;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("ots_getApiLevel", get_otterscan_api_level),
            ("ots_getBlockDetails", get_block_details),
            ("ots_getBlockDetailsByHash", get_block_details_by_hash),
        ],
    )
}

fn get_otterscan_api_level(_: Params, _: &Arc<Mutex<Node>>) -> Result<u64> {
    // https://github.com/otterscan/otterscan/blob/0a819f3557fe19c0f47327858261881ec5f56d6c/src/params.ts#L1
    Ok(8)
}

fn get_block_details(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<OtterscanBlockDetails>> {
    let block: u64 = params.one()?;

    let block = node
        .lock()
        .unwrap()
        .get_block_by_view(block)
        .map(OtterscanBlockDetails::from);

    Ok(block)
}

fn get_block_details_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<OtterscanBlockDetails>> {
    let block_hash: H256 = params.one()?;

    let block = node
        .lock()
        .unwrap()
        .get_block_by_hash(Hash(block_hash.0))
        .map(OtterscanBlockDetails::from);

    Ok(block)
}
