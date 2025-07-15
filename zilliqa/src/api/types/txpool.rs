use std::collections::HashMap;

use alloy::primitives::Address;
use serde::Serialize;

use super::eth::Transaction;

#[derive(Clone, Serialize)]
pub struct TxPoolContent {
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub pending: HashMap<Address, HashMap<u64, Transaction>>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub queued: HashMap<Address, HashMap<u64, Transaction>>,
}

#[derive(Clone, Serialize)]
pub struct TxPoolInspect {
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub pending: HashMap<Address, HashMap<u64, String>>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub queued: HashMap<Address, HashMap<u64, String>>,
}

#[derive(Clone, Serialize)]
pub struct TxPoolStatus {
    pub pending: u64,
    pub queued: u64,
}
