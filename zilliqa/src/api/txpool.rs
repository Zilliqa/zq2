use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use alloy::primitives::Address;
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
fn txpool_content_from(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<types::txpool::TxPoolContent> {
    let address: super::zilliqa::ZilAddress = params.one()?;
    let address: Address = address.into();
    let node = node.lock().unwrap();
    let content = node.txpool_content()?;

    let mut result = types::txpool::TxPoolContent {
        pending: HashMap::new(),
        queued: HashMap::new(),
    };

    for item in content.pending {
        if item.signer == address {
            let txns = result.pending.entry(item.signer).or_default();
            txns.insert(
                item.tx.nonce().unwrap(),
                Transaction::new(item.clone(), None),
            );
        }
    }

    for item in content.queued {
        if item.signer == address {
            let txns = result.queued.entry(item.signer).or_default();
            txns.insert(
                item.tx.nonce().unwrap(),
                Transaction::new(item.clone(), None),
            );
        }
    }

    Ok(result)
}

/// txpool_inspect
fn txpool_inspect(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<types::txpool::TxPoolInspect> {
    let node = node.lock().unwrap();
    let content = node.txpool_content()?;

    let mut result = types::txpool::TxPoolInspect {
        pending: HashMap::new(),
        queued: HashMap::new(),
    };

    for item in content.pending {
        let txns = result.pending.entry(item.signer).or_default();
        let txn = Transaction::new(item.clone(), None);
        let summary = format!(
            "{}: {} wei + {} × {} wei",
            txn.to.unwrap_or_default(),
            txn.value,
            txn.gas,
            txn.gas_price
        );
        txns.insert(item.tx.nonce().unwrap(), summary);
    }

    for item in content.queued {
        let txns = result.queued.entry(item.signer).or_default();
        let txn = Transaction::new(item.clone(), None);
        let summary = format!(
            "{}: {} wei + {} × {} wei",
            txn.to.unwrap_or_default(),
            txn.value,
            txn.gas,
            txn.gas_price
        );
        txns.insert(item.tx.nonce().unwrap(), summary);
    }

    Ok(result)
}

/// txpool_status
fn txpool_status(_params: Params, node: &Arc<Mutex<Node>>) -> Result<types::txpool::TxPoolStatus> {
    let node = node.lock().unwrap();
    let content = node.txpool_content()?;

    Ok(types::txpool::TxPoolStatus {
        pending: content.pending.len() as u64,
        queued: content.queued.len() as u64,
    })
}
