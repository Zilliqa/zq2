#![allow(unused_imports)]
use crate::cfg::{NodeConfig, UCCBConfig, UCCBNetwork};
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
use crate::uccb::signatures::Signatures;
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::Provider;
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
use std::{
    str::FromStr,
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

/// Necessary because the way we send data to shards is fundamentally not RPC, so we need an abstraction.
pub struct UCCBProvider {
    pub chain_gateway_address: Address,
    pub chain_id: u64,
    // If None, this is a local chain.
    pub external_ref: Option<UCCBNetwork>,
    pub key: SigningKey,
}

impl UCCBProvider {
    pub fn from_local(chain_gateway_address: Address, chain_id: u64, key: SigningKey) -> Self {
        Self {
            chain_gateway_address,
            chain_id,
            external_ref: None,
            key,
        }
    }

    pub fn from_external(config: &UCCBNetwork, key: SigningKey) -> Self {
        Self {
            chain_gateway_address: config.chain_gateway,
            chain_id: config.chain_id,
            external_ref: Some(config.clone()),
            key,
        }
    }

    // Has to be mut, because I need to update the nonce :-(
    pub fn send_dispatch(&mut self, _call: &Bytes) -> Result<TxHash> {
        Err(anyhow!("Not implemented"))
    }
}
