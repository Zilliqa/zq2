use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicPtr, AtomicUsize},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Result, anyhow};
use http::{Method, header};
use libp2p::{PeerId, futures::StreamExt};
use node::Node;
use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions::{
    attribute::{
        ERROR_TYPE, MESSAGING_DESTINATION_NAME, MESSAGING_OPERATION_NAME, MESSAGING_SYSTEM,
    },
    metric::MESSAGING_PROCESS_DURATION,
};
use parking_lot::RwLock;
use tokio::{
    select,
    sync::mpsc::{self, UnboundedSender},
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tower_http::cors::{Any, CorsLayer};
use tracing::*;

use crate::{
    api::{self, subscription_id_provider::EthIdProvider},
    cfg::NodeConfig,
    crypto::SecretKey,
    health::HealthLayer,
    message::{ExternalMessage, InternalMessage},
    node::{self, OutgoingMessageFailure},
    p2p_node::{LocalMessageTuple, OutboundMessageTuple},
    sync::SyncPeers,
};

pub struct NodeLauncher {
    pub node: Arc<RwLock<Node>>,
    pub config: NodeConfig,
    pub broadcasts: UnboundedReceiverStream<(PeerId, ExternalMessage)>,
    pub requests: UnboundedReceiverStream<(PeerId, String, ExternalMessage, ResponseChannel)>,
    pub request_failures: UnboundedReceiverStream<(PeerId, OutgoingMessageFailure)>,
    pub responses: UnboundedReceiverStream<(PeerId, ExternalMessage)>,
    pub local_messages: UnboundedReceiverStream<(u64, InternalMessage)>,
    /// Channel used to steer next sleep time
    pub reset_timeout_receiver: UnboundedReceiverStream<Duration>,
    node_launched: bool,
}

// If the `fake_response_channel` feature is enabled, swap out the libp2p ResponseChannel for a `u64`. In our
// integration tests we are not able to construct a ResponseChannel manually, so we need an alternative way of linking
// a request and a response.
#[cfg(not(feature = "fake_response_channel"))]
type ChannelType = libp2p::request_response::ResponseChannel<ExternalMessage>;
#[cfg(feature = "fake_response_channel")]
type ChannelType = u64;

/// A wrapper around [libp2p::request_response::ResponseChannel] which also handles the case where the node has sent a
/// request to itself. In this case, we don't require a response.
#[derive(Debug)]
#[cfg_attr(feature = "fake_response_channel", derive(Clone, Hash, PartialEq, Eq))]
pub enum ResponseChannel {
    Local,
    Remote(ChannelType),
}

impl ResponseChannel {
    pub fn into_inner(self) -> Option<ChannelType> {
        match self {
            ResponseChannel::Local => None,
            ResponseChannel::Remote(c) => Some(c),
        }
    }
}

/// The collection of channels used to send messages to a [NodeLauncher].
pub struct NodeInputChannels {
    /// Send broadcast messages (received via gossipsub) down this channel.
    pub broadcasts: UnboundedSender<(PeerId, ExternalMessage)>,
    /// Send direct requests down this channel. The `ResponseChannel` must be used by the receiver to respond to this
    /// request.
    pub requests: UnboundedSender<(PeerId, String, ExternalMessage, ResponseChannel)>,
    /// Send failed requests down this channel.
    pub request_failures: UnboundedSender<(PeerId, OutgoingMessageFailure)>,
    /// Send direct responses to direct requests down this channel.
    pub responses: UnboundedSender<(PeerId, ExternalMessage)>,
    /// Send local messages down this channel. This is used to forward cross-shard messages to the node.
    pub local_messages: UnboundedSender<(u64, InternalMessage)>,
}

impl NodeLauncher {
    pub async fn new(
        secret_key: SecretKey,
        config: NodeConfig,
        outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
        local_outbound_message_sender: UnboundedSender<LocalMessageTuple>,
        request_responses_sender: UnboundedSender<(ResponseChannel, ExternalMessage)>,
        peer_num: Arc<AtomicUsize>,
        swarm_peers: Arc<AtomicPtr<Vec<PeerId>>>,
    ) -> Result<(Self, NodeInputChannels, Arc<SyncPeers>)> {
        /// Helper to create a (sender, receiver) pair for a channel.
        fn sender_receiver<T>() -> (UnboundedSender<T>, UnboundedReceiverStream<T>) {
            let (sender, receiver) = mpsc::unbounded_channel();
            (sender, UnboundedReceiverStream::new(receiver))
        }

        let (broadcasts_sender, broadcasts_receiver) = sender_receiver();
        let (requests_sender, requests_receiver) = sender_receiver();
        let (request_failures_sender, request_failures_receiver) = sender_receiver();
        let (responses_sender, responses_receiver) = sender_receiver();
        let (local_messages_sender, local_messages_receiver) = sender_receiver();
        let (reset_timeout_sender, reset_timeout_receiver) = sender_receiver();

        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let sync_peers = Arc::new(SyncPeers::new(peer_id));

        let node = Node::new(
            config.clone(),
            secret_key,
            outbound_message_sender,
            local_outbound_message_sender,
            request_responses_sender,
            reset_timeout_sender.clone(),
            peer_num,
            sync_peers.clone(),
            swarm_peers.clone(),
        )?;

        let node = Arc::new(RwLock::new(node));

        for api_server in &config.api_servers {
            let rpc_module = api::rpc_module(Arc::clone(&node), &api_server.enabled_apis);
            // Construct the JSON-RPC API server. We inject a [CorsLayer] to ensure web browsers can call our API directly.
            let cors = CorsLayer::new()
                .allow_methods(Method::POST)
                .allow_origin(Any)
                .allow_headers([header::CONTENT_TYPE]);
            let middleware = tower::ServiceBuilder::new().layer(HealthLayer).layer(cors);
            let server = jsonrpsee::server::ServerBuilder::new()
                .max_response_body_size(config.max_rpc_response_size)
                .set_http_middleware(middleware)
                .set_id_provider(EthIdProvider)
                .build((Ipv4Addr::UNSPECIFIED, api_server.port))
                .await;

            match server {
                Ok(server) => {
                    let port = server.local_addr()?.port();
                    info!("JSON-RPC server listening on port {}", port);
                    let handle = server.start(rpc_module);
                    tokio::spawn(handle.stopped());
                }
                Err(e) => {
                    error!("Failed to start JSON-RPC server: {}", e);
                }
            }
        }

        let launcher = NodeLauncher {
            node,
            broadcasts: broadcasts_receiver,
            requests: requests_receiver,
            request_failures: request_failures_receiver,
            responses: responses_receiver,
            local_messages: local_messages_receiver,
            reset_timeout_receiver,
            node_launched: false,
            config,
        };
        let input_channels = NodeInputChannels {
            broadcasts: broadcasts_sender,
            requests: requests_sender,
            request_failures: request_failures_sender,
            responses: responses_sender,
            local_messages: local_messages_sender,
        };

        Ok((launcher, input_channels, sync_peers))
    }

    pub async fn start_shard_node(&mut self) -> Result<()> {
        if self.node_launched {
            return Err(anyhow!("Node already running!"));
        }

        let consensus_sleep = time::sleep(Duration::from_millis(5));
        tokio::pin!(consensus_sleep);

        let mempool_sleep = time::sleep(Duration::from_millis(5));
        tokio::pin!(mempool_sleep);

        self.node_launched = true;

        let meter = opentelemetry::global::meter("zilliqa");
        let messaging_process_duration = meter
            .f64_histogram(MESSAGING_PROCESS_DURATION)
            .with_unit("s")
            .with_boundaries(vec![
                0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
            ])
            .build();

        loop {
            select! {
                message = self.broadcasts.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    let mut attributes = vec![
                        KeyValue::new(MESSAGING_OPERATION_NAME, "handle"),
                        KeyValue::new(MESSAGING_SYSTEM, "tokio_channel"),
                        KeyValue::new(MESSAGING_DESTINATION_NAME, "broadcast"),
                    ];

                    let start = SystemTime::now();
                    if let ExternalMessage::BatchedTransactions(transactions) = message {
                        let my_peer_id = self.node.write().consensus.peer_id();

                        if source == my_peer_id {
                            continue;
                        }
                        let mut verified = Vec::new();
                        for txn in transactions {
                            let txn = txn.verify()?;
                            verified.push(txn);
                        }
                        self.node.write().handle_broadcasted_transactions(verified)?;
                    }
                    else if let Err(e) = self.node.write().handle_broadcast(source, message) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process broadcast message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes,
                    );
                }
                message = self.requests.next() => {
                    let (source, id, message, response_channel) = message.expect("message stream should be infinite");
                    let mut attributes = vec![
                        KeyValue::new(MESSAGING_OPERATION_NAME, "handle"),
                        KeyValue::new(MESSAGING_SYSTEM, "tokio_channel"),
                        KeyValue::new(MESSAGING_DESTINATION_NAME, "request"),
                    ];

                    let start = SystemTime::now();
                    if let Err(e) = self.node.write().handle_request(source, &id, message, response_channel) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process request message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes,
                    );
                }
                message = self.request_failures.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    let mut attributes = vec![
                        KeyValue::new(MESSAGING_OPERATION_NAME, "handle"),
                        KeyValue::new(MESSAGING_SYSTEM, "tokio_channel"),
                        KeyValue::new(MESSAGING_DESTINATION_NAME, "request_failure"),
                    ];

                    let start = SystemTime::now();
                    if let Err(e) = self.node.write().handle_request_failure(source, message) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process request failure message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes,
                    );
                }
                message = self.responses.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    let mut attributes = vec![
                        KeyValue::new(MESSAGING_OPERATION_NAME, "handle"),
                        KeyValue::new(MESSAGING_SYSTEM, "tokio_channel"),
                        KeyValue::new(MESSAGING_DESTINATION_NAME, "response"),
                    ];

                    let start = SystemTime::now();
                    if let Err(e) = self.node.write().handle_response(source, message) {
                        attributes.push(KeyValue::new(ERROR_TYPE, "process-error"));
                        error!("Failed to process response message: {e}");
                    }
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes,
                    );
                }
                message = self.local_messages.next() => {
                    let (_source, _message) = message.expect("message stream should be infinite");
                    todo!("Local messages will need to be handled once cross-shard messaging is implemented");
                }
                () = &mut consensus_sleep => {
                    let attributes = vec![
                        KeyValue::new(MESSAGING_OPERATION_NAME, "handle"),
                        KeyValue::new(MESSAGING_SYSTEM, "tokio_channel"),
                        KeyValue::new(MESSAGING_DESTINATION_NAME, "timeout"),
                    ];

                    let start = SystemTime::now();
                    // No messages for a while, so check if consensus wants to timeout
                    self.node.write().handle_timeout().unwrap();
                    consensus_sleep.as_mut().reset(Instant::now() + Duration::from_millis(500));
                    messaging_process_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                        &attributes,
                    );
                },
                r = self.reset_timeout_receiver.next() => {
                    let sleep_time = r.expect("reset timeout stream should be infinite");
                    trace!(?sleep_time, "timeout reset");
                    consensus_sleep.as_mut().reset(Instant::now() + sleep_time);
                },

                () = &mut mempool_sleep => {
                    self.node.write().process_transactions_to_broadcast()?;
                    mempool_sleep.as_mut().reset(Instant::now() + Duration::from_millis(100));
                },
            }
        }
    }
}
