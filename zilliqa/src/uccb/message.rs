//! Message types for UCCB

use crate::uccb::contracts::{IDISPATCHER_EVENTS, IRELAYER_EVENTS};
use alloy::primitives::{Address, Bytes, TxHash, U256};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UCCBExternalMessage {
    Hello,
    // Here's a signature
    Signature(SignedRelayedMessage),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UCCBInternalMessage {
    HelloInternal,
    /// Request a scan for this block on our chain.
    RequestScan(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayedMessage {
    pub source_chain_id: U256,
    pub block_number: u64,
    pub tx_hash: TxHash,
    pub log_index: u64,
    pub target_chain_id: U256,
    pub target: Address,
    pub call: Bytes,
    pub gas_limit: U256,
    pub nonce: U256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRelayedMessage {
    pub message: RelayedMessage,
    pub signatures: HashMap<PeerId, Bytes>,
}

/// We always specify chain ids as the source and destination of the bridge request
/// hence, a DispatchedMessage arrives on the _destination_ chain (of the bridge request)
/// and is sent to the source chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchedMessage {
    pub destination_chain_id: U256,
    pub block_number: u64,
    pub tx_hash: TxHash,
    pub log_index: u64,
    pub source_chain_id: U256,
    pub target: Address,
    pub success: bool,
    pub response: Bytes,
    pub nonce: U256,
}

impl RelayedMessage {
    pub fn from_relayed_event(
        source_chain_id: U256,
        block_number: u64,
        log_index: u64,
        tx_hash: TxHash,
        relayed: &IRELAYER_EVENTS::Relayed,
    ) -> RelayedMessage {
        Self {
            source_chain_id,
            block_number,
            tx_hash,
            log_index,
            target_chain_id: relayed.targetChainId,
            target: relayed.target,
            call: relayed.call.clone(),
            gas_limit: relayed.gasLimit,
            nonce: relayed.nonce,
        }
    }
}

impl SignedRelayedMessage {
    pub fn from_message(message: RelayedMessage) -> Self {
        SignedRelayedMessage {
            message,
            signatures: HashMap::new(),
        }
    }

    // Possibly a bit too functional ..
    pub fn with_signature(&self, id: PeerId, signature: &[u8; 65]) -> Self {
        let mut next = self.clone();
        next.signatures
            .insert(id, Bytes::copy_from_slice(signature));
        next
    }
}

impl DispatchedMessage {
    pub fn from_dispatched_event(
        destination_chain_id: U256,
        block_number: u64,
        log_index: u64,
        tx_hash: TxHash,
        dispatched: &IDISPATCHER_EVENTS::Dispatched,
    ) -> DispatchedMessage {
        Self {
            destination_chain_id,
            block_number,
            tx_hash,
            log_index,
            source_chain_id: dispatched.sourceChainId,
            target: dispatched.target,
            success: dispatched.success,
            response: dispatched.response.clone(),
            nonce: dispatched.nonce,
        }
    }
}
