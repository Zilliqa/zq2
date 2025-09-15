use std::{collections::HashMap, sync::Arc};

use alloy::primitives::Address;
use anyhow::Result;
use jsonrpsee::{RpcModule, types::Params};

use super::types;
use crate::{api::types::eth::Transaction, cfg::EnabledApi, node::Node};

pub fn rpc_module(
    node: Arc<Node>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Node>> {
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
    node: &Arc<Node>,
) -> Result<Option<types::txpool::TxPoolContent>> {
    let content = node.txpool_content();

    let pending: HashMap<Address, HashMap<u64, Transaction>> = content
        .pending
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                v.iter()
                    .filter(|x| x.tx.nonce().is_some())
                    .map(|x| (x.tx.nonce().unwrap(), Transaction::new(x.clone(), None)))
                    .collect::<HashMap<u64, Transaction>>(),
            )
        })
        .filter(|(_, v)| !v.is_empty())
        .collect();

    let queued: HashMap<Address, HashMap<u64, Transaction>> = content
        .queued
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                v.iter()
                    .filter(|x| x.tx.nonce().is_some())
                    .map(|x| (x.tx.nonce().unwrap(), Transaction::new(x.clone(), None)))
                    .collect::<HashMap<u64, Transaction>>(),
            )
        })
        .filter(|(_, v)| !v.is_empty())
        .collect();

    let result = types::txpool::TxPoolContent { pending, queued };

    Ok(Some(result))
}

/// txpool_contentFrom
fn txpool_content_from(
    params: Params,
    node: &Arc<Node>,
) -> Result<types::txpool::TxPoolContent> {
    let address: super::zilliqa::ZilAddress = params.one()?;
    let address: Address = address.into();
    let content = node.txpool_content_from(&address);

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
    node: &Arc<Node>,
) -> Result<types::txpool::TxPoolInspect> {
    let content = node.txpool_content();

    let mut result = types::txpool::TxPoolInspect {
        pending: HashMap::new(),
        queued: HashMap::new(),
    };

    for item in content.pending.values().flatten() {
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

    for item in content.queued.values().flatten() {
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
fn txpool_status(_params: Params, node: &Arc<Node>) -> Result<types::txpool::TxPoolStatus> {
    let content = node.txpool_status();

    Ok(types::txpool::TxPoolStatus {
        pending: content.pending,
        queued: content.queued,
    })
}
