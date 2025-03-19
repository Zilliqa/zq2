#![allow(unused_imports)]
//! UCCB node.

use crate::cfg::NodeConfig;
use crate::message::ExternalMessage;
use crate::p2p_node::{LocalMessageTuple, OutboundMessageTuple};
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use crate::{
    node::Node,
    uccb::message::{UCCBExternalMessage, UCCBInternalMessage},
    uccb::node::UCCBNode,
};
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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct UCCBRequestId(u64);

impl UCCBRequestId {
    pub fn from_u64(u: u64) -> Self {
        Self(u)
    }
}

pub type UCCBOutboundMessageTuple = (Option<(PeerId, UCCBRequestId)>, u64, UCCBExternalMessage);
pub type UCCBLocalMessageTuple = (u64, u64, UCCBInternalMessage);

#[derive(Debug)]
pub struct UCCBMessageFailure {
    pub peer: PeerId,
    pub request_id: UCCBRequestId,
}

pub struct UCCBLauncher {
    pub node: Arc<Mutex<UCCBNode>>,
    pub config: NodeConfig,
    pub broadcasts: UnboundedReceiverStream<(PeerId, UCCBExternalMessage)>,
    pub requests: UnboundedReceiverStream<(PeerId, String, UCCBExternalMessage, ResponseChannel)>,
    pub request_failures: UnboundedReceiverStream<(PeerId, UCCBMessageFailure)>,
    pub responses: UnboundedReceiverStream<(PeerId, UCCBExternalMessage)>,
    pub local_messages: UnboundedReceiverStream<(u64, UCCBInternalMessage)>,
    pub tick_receiver: UnboundedReceiverStream<Duration>,
    node_launched: bool,
}

pub struct UCCBInputChannels {
    pub broadcasts: UnboundedSender<(PeerId, UCCBExternalMessage)>,
    pub requests: UnboundedSender<(PeerId, String, UCCBExternalMessage, ResponseChannel)>,
    pub request_failures: UnboundedSender<(PeerId, UCCBMessageFailure)>,
    pub responses: UnboundedSender<(PeerId, UCCBExternalMessage)>,
    pub local_messages: UnboundedSender<(u64, UCCBInternalMessage)>,
}

// If the `fake_response_channel` feature is enabled, swap out the libp2p ResponseChannel for a `u64`. In our
// integration tests we are not able to construct a ResponseChannel manually, so we need an alternative way of linking
// a request and a response.
#[cfg(not(feature = "fake_response_channel"))]
type ChannelType = libp2p::request_response::ResponseChannel<UCCBExternalMessage>;
#[cfg(feature = "fake_response_channel")]
type ChannelType = u64;

/// A wrapper around [libp2p::request_response::ResponseChannel] which also handles the case where the node has sent a
/// request to itself. In this case, we don't require a response.
#[derive(Debug)]
#[cfg_attr(feature = "fake_response_channel", derive(Clone, Hash, PartialEq, Eq))]
pub enum UCCBResponseChannel {
    Local,
    Remote(ChannelType),
}

impl UCCBResponseChannel {
    pub fn into_inner(self) -> Option<ChannelType> {
        match self {
            UCCBResponseChannel::Local => None,
            UCCBResponseChannel::Remote(c) => Some(c),
        }
    }
}

impl UCCBLauncher {
    pub async fn new(
        secret_key: SecretKey,
        config: NodeConfig,
        host: Arc<Mutex<Node>>,
        outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
        local_outbound_message_sender: UnboundedSender<LocalMessageTuple>,
        request_responses_sender: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    ) -> Result<(Self, UCCBInputChannels, Arc<SyncPeers>)> {
        fn sender_receiver<T>() -> (UnboundedSender<T>, UnboundedReceiverStream<T>) {
            let (sender, receiver) = mpsc::unbounded_channel();
            (sender, UnboundedReceiverStream::new(receiver))
        }

        let (broadcasts_sender, broadcasts_receiver) = sender_receiver();
        let (requests_sender, requests_receiver) = sender_receiver();
        let (request_failures_sender, request_failures_receiver) = sender_receiver();
        let (responses_sender, responses_receiver) = sender_receiver();
        let (local_messages_sender, local_messages_receiver) = sender_receiver();
        let (_tick_receiver_sender, tick_receiver_receiver) = sender_receiver();

        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let peers: Arc<SyncPeers> = Arc::new(SyncPeers::new(peer_id));
        let node = Arc::new(Mutex::new(UCCBNode::new(
            secret_key.to_signing_key(),
            peer_id,
            config.clone(),
            outbound_message_sender,
            local_outbound_message_sender,
            request_responses_sender,
            host,
        )?));

        // We don't (yet!) have an API server.
        let launcher = UCCBLauncher {
            node,
            config,
            broadcasts: broadcasts_receiver,
            requests: requests_receiver,
            request_failures: request_failures_receiver,
            responses: responses_receiver,
            local_messages: local_messages_receiver,
            tick_receiver: tick_receiver_receiver,
            node_launched: false,
        };
        let input_channels = UCCBInputChannels {
            broadcasts: broadcasts_sender,
            requests: requests_sender,
            request_failures: request_failures_sender,
            responses: responses_sender,
            local_messages: local_messages_sender,
        };
        Ok((launcher, input_channels, peers))
    }

    pub async fn start_uccb_node(&mut self) -> Result<()> {
        if self.node_launched {
            return Err(anyhow!("UCCB node already running"));
        }
        let tick_time = time::sleep(Duration::from_millis(5));
        tokio::pin!(tick_time);

        self.node_launched = true;

        // Start the external monitor threads.
        UCCBNode::start_external_networks(self.node.clone()).await?;

        let meter = opentelemetry::global::meter("uccb");
        let messaging_process_duration = meter
            .f64_histogram(MESSAGING_PROCESS_DURATION)
            .with_unit("s")
            .with_boundaries(vec![
                0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
            ])
            .build();

        fn get_attributes(name: &str) -> Vec<KeyValue> {
            vec![
                KeyValue::new(MESSAGING_OPERATION_NAME, "handle"),
                KeyValue::new(MESSAGING_SYSTEM, "tokio_channel"),
                KeyValue::new(MESSAGING_DESTINATION_NAME, name.to_string()),
            ]
        }

        loop {
            select! {
                message = self.broadcasts.next() => {
                    let (source, message) = message.expect("uccb b/cast message stream should be infinite");
                    let start = SystemTime::now();
                    let mut attributes = get_attributes("broadcast");
                    if let Err(e) = self.node.lock().unwrap().handle_broadcast(source, message) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process broadcast message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes);
                }
                message = self.requests.next() => {
                    let (source, id, message, response_channel) = message.expect("uccb request message stream should be infinite");
                    let start = SystemTime::now();
                    let mut attributes = get_attributes("request");
                    if let Err(e) = self.node.lock().unwrap().handle_request(source, &id, message, response_channel) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process request message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes);
                },
                message = self.request_failures.next() => {
                    let (source, message) = message.expect("uccb request_failures message stream should be infinite");
                    let start = SystemTime::now();
                    let mut attributes = get_attributes("request-failure");
                    if let Err(e) = self.node.lock().unwrap().handle_request_failure(source, message) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process request message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes);
                },
                message = self.responses.next() => {
                    let (source, message) = message.expect("uccb responses message stream should be infinite");
                    let start = SystemTime::now();
                    let mut attributes = get_attributes("response");
                    if let Err(e) = self.node.lock().unwrap().handle_response(source, message) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process response message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes);
                },
                message = self.local_messages.next() => {
                    let (source, message) = message.expect("uccb responses message stream should be infinite");
                    let start = SystemTime::now();
                    let mut attributes = get_attributes("local");
                    if let Err(e) = crate::uccb::node::handle_local(self.node.clone(), source, message).await {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process local message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes);
                },
                () = &mut tick_time => {
                    let attributes = get_attributes("tick");
                    let start = SystemTime::now();
                    info!("Before handle");
                    self.node.lock().unwrap().handle_tick()?;
                    info!("After handle");
                    tick_time.as_mut().reset(Instant::now() + Duration::from_millis(1000));
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes);
                }
            }
        }
    }
}
