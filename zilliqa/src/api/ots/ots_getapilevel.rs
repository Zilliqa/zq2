use crate::node::Node;
use anyhow::Result;
use jsonrpsee::types::Params;
use std::sync::{Arc, Mutex};

pub fn get_otterscan_api_level(_: Params, _: &Arc<Mutex<Node>>) -> Result<u64> {
    // https://github.com/otterscan/otterscan/blob/0a819f3557fe19c0f47327858261881ec5f56d6c/src/params.ts#L1
    Ok(8)
}
