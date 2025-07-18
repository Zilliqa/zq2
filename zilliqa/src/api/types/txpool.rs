use std::collections::HashMap;

use alloy::primitives::Address;
use serde::Serialize;

use super::eth::Transaction;

#[derive(Clone, Serialize)]
pub struct TxPoolContent {
    pub pending: HashMap<Address, HashMap<u64, Transaction>>,
    pub queued: HashMap<Address, HashMap<u64, Transaction>>,
}

#[derive(Clone, Serialize)]
pub struct TxPoolInspect {
    pub pending: HashMap<Address, HashMap<u64, String>>,
    pub queued: HashMap<Address, HashMap<u64, String>>,
}

#[derive(Clone, Serialize)]
pub struct TxPoolStatus {
    pub pending: u64,
    pub queued: u64,
}
