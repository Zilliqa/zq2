use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use alloy_rpc_types_trace::parity::{TraceResults, TraceType};
use anyhow::Result;
use jsonrpsee::{types::Params, RpcModule};

use crate::{crypto::Hash, node::Node};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(node, [("trace_replayTransaction", replay_transaction)])
}

fn replay_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<TraceResults> {
    let mut params = params.sequence();
    let txn_hash: B256 = params.next()?;
    let txn_hash: Hash = txn_hash.into();
    let trace_types: HashSet<TraceType> = params.next()?;

    let trace = node
        .lock()
        .unwrap()
        .trace_evm_transaction(txn_hash, &trace_types)?;

    Ok(trace)
}
