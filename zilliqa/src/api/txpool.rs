use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use super::types::eth;
use crate::{api::types::eth::Transaction, cfg::EnabledApi, node::Node};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, enabled_apis, [("txpool_content", txpool_content)])
}

fn txpool_content(_params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::TxPoolContent>> {
    let node = node.lock().unwrap();
    let content = node.txpool_content()?;

    let mut result = eth::TxPoolContent {
        pending: HashMap::new(),
        queued: HashMap::new(),
    };

    for item in content.pending {
        let txns = result.pending.entry(item.signer).or_default();
        txns.insert(
            item.tx.nonce().unwrap(),
            Transaction::new(item.clone(), None),
        );
    }

    for item in content.queued {
        let txns = result.queued.entry(item.signer).or_default();
        txns.insert(
            item.tx.nonce().unwrap(),
            Transaction::new(item.clone(), None),
        );
    }

    Ok(Some(result))
}
