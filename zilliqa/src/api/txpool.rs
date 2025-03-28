use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use jsonrpsee::{RpcModule, types::Params};

use super::types;
use crate::{api::types::eth::Transaction, cfg::EnabledApi, node::Node};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            ("txpool_content", txpool_content),
            ("txpool_contentFrom", txpool_content_from),
            ("txpool_inspect", txpool_inspect),
            ("txpool_status", txpool_status),
        ]
    )
}

/// txpool_content
fn txpool_content(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<types::txpool::TxPoolContent>> {
    let node = node.lock().unwrap();
    let content = node.txpool_content()?;

    let mut result = types::txpool::TxPoolContent {
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

/// txpool_contentFrom
fn txpool_content_from(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// txpool_inspect
fn txpool_inspect(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// txpool_status
fn txpool_status(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}
