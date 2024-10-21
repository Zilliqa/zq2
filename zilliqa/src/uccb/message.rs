// ! taken from ZQ2

use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

use alloy::primitives::{Address, Signature, U256};
use serde::{Deserialize, Serialize};

use crate::uccb::event::RelayedEvent;

#[derive(Clone, Serialize, Deserialize)]
pub struct Relay {
    pub event: RelayedEvent,
    pub signature: Signature,
}

impl Debug for Relay {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Relay event: [source_chain: {}, target_chain: {}, nonce: {}]",
            self.event.source_chain_id, self.event.target_chain_id, self.event.nonce
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispatched {
    pub chain_id: U256,
    pub nonce: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispatch {
    pub event: RelayedEvent,
    pub signatures: BTreeMap<Address, Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InboundBridgeMessage {
    Dispatched(Dispatched),
    Relay(Relay),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutboundBridgeMessage {
    Dispatch(Dispatch),
    Dispatched(Dispatched),
    Relay(Relay),
}
