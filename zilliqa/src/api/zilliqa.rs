//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::{panic::AssertUnwindSafe, sync::Arc};
use tokio::sync::Mutex;

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use crate::node::Node;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("GetCurrentMiniEpoch", get_current_mini_epoch),
            ("GetVersion", get_git_commit),
        ],
    )
}

async fn get_current_mini_epoch(_: Params<'_>, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().await.view().to_string())
}

async fn get_git_commit(_: Params<'_>, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(env!("VERGEN_GIT_DESCRIBE").to_string())
}
