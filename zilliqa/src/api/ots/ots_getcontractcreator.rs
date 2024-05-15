use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use anyhow::Result;
use jsonrpsee::types::Params;
use serde_json::{json, Value};

use crate::{api::to_hex::ToHex, inspector::CreatorInspector, node::Node};

pub(crate) fn get_contract_creator(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<Value>> {
    let address: Address = params.one()?;

    let touched = node.lock().unwrap().get_touched_transactions(address)?;

    // Perform a linear search over each transaction which touched this address. Replay each one to try and find the
    // transaction which created it.
    for txn_hash in touched {
        // Replay the creation transaction to work out the creator. This is important for contracts which are created
        // by other contracts, for which the creator is not the same as `txn.from_addr`.
        let mut inspector = CreatorInspector::new(address);
        node.lock()
            .unwrap()
            .replay_transaction(txn_hash, &mut inspector)?;

        if let Some(creator) = inspector.creator() {
            return Ok(Some(json!({
                "hash": B256::from(txn_hash).to_hex(),
                "creator": creator.to_hex(),
            })));
        }
    }

    Ok(None)
}
