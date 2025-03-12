#![allow(unused_imports)]
use crate::cfg::{NodeConfig, UCCBConfig};
use crate::message::ExternalMessage;
use crate::p2p_node::{LocalMessageTuple, OutboundMessageTuple};
use crate::uccb::launcher::{
    UCCBLocalMessageTuple, UCCBMessageFailure, UCCBOutboundMessageTuple, UCCBRequestId,
    UCCBResponseChannel,
};
use crate::uccb::message::{UCCBExternalMessage, UCCBInternalMessage};
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use anyhow::{Result, anyhow};
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

// For the sake of some sort of sanity, we take the global transmission channels here, and
// adapt them in the implementation for the UCCB use case - the alternative would have been
// a lot of code duplication.
#[derive(Debug, Clone)]
pub struct UCCBMessageSender {
    pub our_shard: u64,
    pub our_peer_id: PeerId,
    pub outbound_channel: UnboundedSender<UCCBOutboundMessageTuple>,
    pub local_channel: UnboundedSender<UCCBLocalMessageTuple>,
    pub request_id: UCCBRequestId,
}

// TBD.
impl UCCBMessageSender {}

pub struct UCCBNode {
    pub secret_key: SecretKey,
    pub node_config: NodeConfig,
    pub uccb_config: UCCBConfig,
    pub request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    pub sender: UCCBMessageSender,
}

impl UCCBNode {
    /// Starts up the UCCBNode for NodeConfig.
    pub fn new(
        secret_key: SecretKey,
        node_config: NodeConfig,
        message_sender_channel: UnboundedSender<OutboundMessageTuple>,
        local_sender_channel: UnboundedSender<LocalMessageTuple>,
        request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    ) -> Result<Self> {
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let sender = UCCBMessageSender {
            our_shard: node_config.eth_chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
            local_channel: local_sender_channel,
            request_id: UCCBRequestId::default(),
        };

        let uccb_config = node_config
            .uccb
            .ok_or(anyhow!("No UCCB config when instantiating UCCB node"))?;
        Ok(Self {
            secret_key,
            node_config: node_config.clone(),
            uccb_config,
            request_responses,
            sender,
        })
    }

    pub fn handle_broadcast(&mut self, from: PeerId, message: UCCBExternalMessage) -> Result<()> {
        debug!("uccb_handle_broadcast()");
        Ok(())
    }

    pub fn handle_request(&mut self, from: PeerId, message: UCCBExternalMessage) -> Result<()> {
        debug!("uccb_handle_request()");
        Ok(())
    }

    pub fn handle_request_failure(
        &mut self,
        from: PeerId,
        message: UCCBMessageFailure,
    ) -> Result<()> {
        debug!("uccb_handle_request_failure()");
        Ok(())
    }

    pub fn handle_response(&mut self, from: PeerId, message: UCCBExternalMessage) -> Result<()> {
        debug!("uccb_handle_response()");
        Ok(())
    }

    pub fn handle_local(&mut self, idx: u64, message: UCCBInternalMessage) -> Result<()> {
        debug!("uccb_handle_local()");
        Ok(())
    }

    pub fn handle_tick(&mut self) -> Result<()> {
        debug!("uccb_tick()");
        Ok(())
    }
}
