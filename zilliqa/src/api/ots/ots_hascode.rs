use std::sync::{Arc, Mutex};

use alloy_primitives::Address;
use anyhow::Result;
use jsonrpsee::types::Params;

use crate::{message::BlockNumber, node::Node, state::Contract};

pub(crate) fn has_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<bool> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_number: BlockNumber = params.next()?;

    let contract = node
        .lock()
        .unwrap()
        .get_account(address, block_number)?
        .contract;
    let empty = match contract {
        Contract::Evm { code, .. } => code.is_empty(),
        Contract::Scilla { code, .. } => code.is_empty(),
    };

    Ok(!empty)
}
