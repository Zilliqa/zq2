use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Result};
use http::{header, Method};
use jsonrpsee::RpcModule;
use libp2p::{futures::StreamExt, PeerId};
use node::Node;
use tokio::{
    select,
    sync::{mpsc, mpsc::UnboundedSender},
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
};

pub struct NodeLauncher {
    pub node: Arc<Mutex<Node>>,
    pub config: NodeConfig,
    pub rpc_module: RpcModule<Arc<Mutex<Node>>>,
    pub broadcasts: UnboundedReceiverStream<(PeerId, ExternalMessage)>,
    pub requests: UnboundedReceiverStream<(PeerId, ExternalMessage, ResponseChannel)>,
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
    pub requests: UnboundedSender<(PeerId, ExternalMessage, ResponseChannel)>,
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
    ) -> Result<(Self, NodeInputChannels)> {
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

        let node = Node::new(
            config.clone(),
            secret_key,
            outbound_message_sender,
            local_outbound_message_sender,
            request_responses_sender,
            reset_timeout_sender.clone(),
            peer_num,
        )?;
        let node = Arc::new(Mutex::new(node));

        let rpc_module = api::rpc_module(Arc::clone(&node), config.enable_debug_api);

        if !config.disable_rpc {
            trace!("Launching JSON-RPC server");
            // Construct the JSON-RPC API server. We inject a [CorsLayer] to ensure web browsers can call our API directly.
            let cors = CorsLayer::new()
                .allow_methods(Method::POST)
                .allow_origin(Any)
                .allow_headers([header::CONTENT_TYPE]);
            let middleware = tower::ServiceBuilder::new().layer(HealthLayer).layer(cors);
            let port = config.json_rpc_port;
            let server = jsonrpsee::server::ServerBuilder::new()
                .set_http_middleware(middleware)
                .set_id_provider(EthIdProvider)
                .build((Ipv4Addr::UNSPECIFIED, port))
                .await;

            match server {
                Ok(server) => {
                    info!("JSON-RPC server listening on port {}", port);
                    let handle = server.start(rpc_module.clone());
                    tokio::spawn(handle.stopped());
                }
                Err(e) => {
                    error!("Failed to start JSON-RPC server: {}", e);
                }
            }
        }

        let launcher = NodeLauncher {
            node,
            rpc_module,
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

        Ok((launcher, input_channels))
    }

    pub async fn start_shard_node(&mut self) -> Result<()> {
        if self.node_launched {
            return Err(anyhow!("Node already running!"));
        }

        let sleep = time::sleep(Duration::from_millis(5));
        tokio::pin!(sleep);

        self.node_launched = true;

        loop {
            select! {
                message = self.broadcasts.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    self.node.lock().unwrap().handle_broadcast(source, message).unwrap();
                }
                message = self.requests.next() => {
                    let (source, message, response_channel) = message.expect("message stream should be infinite");
                    self.node.lock().unwrap().handle_request(source, message, response_channel).unwrap();
                }
                message = self.request_failures.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    self.node.lock().unwrap().handle_request_failure(source, message).unwrap();
                }
                message = self.responses.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    self.node.lock().unwrap().handle_response(source, message).unwrap();
                }
                message = self.local_messages.next() => {
                    let (_source, _message) = message.expect("message stream should be infinite");
                    todo!("Local messages will need to be handled once cross-shard messaging is implemented");
                }
                () = &mut sleep => {
                    // Send any missing blocks.
                    self.node.lock().unwrap().consensus.tick().unwrap();
                    // No messages for a while, so check if consensus wants to timeout
                    self.node.lock().unwrap().handle_timeout().unwrap();
                    sleep.as_mut().reset(Instant::now() + Duration::from_millis(500));
                },
                r = self.reset_timeout_receiver.next() => {
                    let sleep_time = r.expect("reset timeout stream should be infinite");
                    trace!(?sleep_time, "timeout reset");
                    sleep.as_mut().reset(Instant::now() + sleep_time);
                },
            }
        }
    }
}
