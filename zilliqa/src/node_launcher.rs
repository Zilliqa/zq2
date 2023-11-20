use crate::p2p_node::LocalMessageTuple;
use crate::{health::HealthLayer, message::ExternalMessage};
use jsonrpsee::RpcModule;
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{api, cfg::NodeConfig, crypto::SecretKey, node, p2p_node::OutboundMessageTuple};

use anyhow::{anyhow, Result};
use http::{header, Method};
use libp2p::{futures::StreamExt, PeerId};

use crate::message::InternalMessage;
use node::Node;
use std::time::Duration;
use tokio::{
    select,
    sync::mpsc,
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tower_http::cors::{Any, CorsLayer};
use tracing::*;

pub struct NodeLauncher {
    pub node: Arc<Mutex<Node>>,
    pub config: NodeConfig,
    pub rpc_module: RpcModule<Arc<Mutex<Node>>>,
    /// The following two message streams are used for networked messages.
    /// The sender is provided to the p2p coordinator, to forward messages to the node.
    pub inbound_message_sender: UnboundedSender<(PeerId, ExternalMessage)>,
    /// The corresponding receiver is handled here, forwarding messages to the node struct.
    pub inbound_message_receiver: UnboundedReceiverStream<(PeerId, ExternalMessage)>,
    /// The following two message streams are used for local messages.
    /// The sender is provided to the p2p coordinator, to forward cross-shard messages to the node.
    pub local_inbound_message_sender: UnboundedSender<(u64, InternalMessage)>,
    /// The corresponding receiver is handled here, forwarding messages to the node struct.
    pub local_inbound_message_receiver: UnboundedReceiverStream<(u64, InternalMessage)>,

    pub reset_timeout_receiver: UnboundedReceiverStream<()>,
    node_launched: bool,
}

impl NodeLauncher {
    pub async fn new(
        secret_key: SecretKey,
        config: NodeConfig,
        outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
        local_outbound_message_sender: UnboundedSender<LocalMessageTuple>,
    ) -> Result<Self> {
        let (inbound_message_sender, inbound_message_receiver) = mpsc::unbounded_channel();
        let inbound_message_receiver = UnboundedReceiverStream::new(inbound_message_receiver);
        let (local_inbound_message_sender, local_inbound_message_receiver) =
            mpsc::unbounded_channel();
        let local_inbound_message_receiver =
            UnboundedReceiverStream::new(local_inbound_message_receiver);
        let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
        let reset_timeout_receiver = UnboundedReceiverStream::new(reset_timeout_receiver);

        let node = Node::new(
            config.clone(),
            secret_key,
            outbound_message_sender.clone(),
            local_outbound_message_sender.clone(),
            reset_timeout_sender.clone(),
        )?;
        let node = Arc::new(Mutex::new(node));

        let rpc_module = api::rpc_module(Arc::clone(&node));

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
                .set_middleware(middleware)
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

        Ok(Self {
            node,
            rpc_module,
            inbound_message_sender,
            inbound_message_receiver,
            reset_timeout_receiver,
            local_inbound_message_sender,
            local_inbound_message_receiver,
            node_launched: false,
            config,
        })
    }

    pub fn message_input(&self) -> UnboundedSender<(PeerId, ExternalMessage)> {
        self.inbound_message_sender.clone()
    }

    pub fn local_message_input(&self) -> UnboundedSender<(u64, InternalMessage)> {
        self.local_inbound_message_sender.clone()
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
                _message = self.local_inbound_message_receiver.next() => {
                    let (_source, _message) = _message.expect("message stream should be infinite");
                    todo!("Local messages will need to be handled once cross-shard messaging is implemented");
                }
                message = self.inbound_message_receiver.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    self.node.lock().unwrap().handle_network_message(source, message).unwrap();
                },
                () = &mut sleep => {
                    // No messages for a while, so check if consensus wants to timeout
                    self.node.lock().unwrap().handle_timeout();
                    sleep.as_mut().reset(Instant::now() + Duration::from_millis(500));
                },
                r = self.reset_timeout_receiver.next() => {
                    let () = r.expect("reset timeout stream should be infinite");
                    trace!("timeout reset");
                    sleep.as_mut().reset(Instant::now() + Duration::from_millis(5000));
                },
            }
        }
    }
}
