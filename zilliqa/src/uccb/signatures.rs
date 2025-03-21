#![allow(unused_imports)]
use crate::cfg::{NodeConfig, UCCBConfig};
use crate::message::{ExternalMessage, InternalMessage};
use crate::node::Node;
use crate::p2p_node::{LocalMessageTuple, OutboundMessageTuple};
use crate::transaction::{EvmLog, Log, TransactionReceipt};
use crate::uccb::contracts::{IDISPATCHER_EVENTS, IRELAYER_EVENTS};
use crate::uccb::external_network::ExternalNetwork;
use crate::uccb::launcher::{
    UCCBLocalMessageTuple, UCCBMessageFailure, UCCBOutboundMessageTuple, UCCBRequestId,
    UCCBResponseChannel,
};
use crate::uccb::message::{
    BridgeEvent, DispatchedMessage, RelayedMessage, SignedEvent, UCCBExternalMessage,
    UCCBInternalMessage,
};
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{TxHash, U256};
use alloy::sol_types::SolEvent;
use anyhow::{Result, anyhow};
use k256::ecdsa::SigningKey;
use libp2p::{PeerId, futures::StreamExt, request_response::OutboundFailure};
use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions::{
    attribute::{
        ERROR_TYPE, MESSAGING_DESTINATION_NAME, MESSAGING_OPERATION_NAME, MESSAGING_SYSTEM,
    },
    metric::MESSAGING_PROCESS_DURATION,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{
    sync::Arc,
    sync::Mutex,
    time::{Duration, SystemTime},
};
use tokio::{
    select,
    sync::mpsc::{self, UnboundedSender, error::SendError},
    task::JoinSet,
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;

// Key for an event.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventKey {
    source_chain_id: U256,
    target_chain_id: U256,
    nonce: U256,
}

/// Stores a collection of signatures, by target chain id and nonce.
/// We need multiple because there may be many copies of an ostensible "Request" broadcast to the network.
/// Only one of them will ever (we hope!) get the required 2/3 signatures.
#[derive(Clone, Debug)]
pub struct Signatures {
    // Maps (chain_id, nonce) -> Event -> signatures
    pub sigs: HashMap<EventKey, HashMap<BridgeEvent, SignedEvent>>,
}

impl EventKey {
    pub fn from_bridge_event(ev: &BridgeEvent) -> Self {
        match ev {
            BridgeEvent::Relayed(r) => Self {
                source_chain_id: r.source_chain_id,
                target_chain_id: r.target_chain_id,
                nonce: r.nonce,
            },
            BridgeEvent::Dispatched(d) => Self {
                source_chain_id: d.source_chain_id,
                target_chain_id: d.target_chain_id,
                nonce: d.nonce,
            },
        }
    }
}

impl std::default::Default for Signatures {
    fn default() -> Self {
        Signatures {
            sigs: HashMap::new(),
        }
    }
}

impl Signatures {
    pub fn new() -> Self {
        Signatures {
            sigs: HashMap::new(),
        }
    }

    pub fn put(&mut self, ev: SignedEvent) -> Result<SignedEvent> {
        let entry_key = EventKey::from_bridge_event(&ev.event);
        let resulting = self
            .sigs
            .entry(entry_key)
            .or_default()
            .entry(ev.event.clone())
            .and_modify(|e| e.merge_signatures(&ev.signatures))
            .or_insert(ev);
        Ok(resulting.clone())
    }
}
