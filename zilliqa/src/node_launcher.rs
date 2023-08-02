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

use node::Node;
use tokio::{
    select,
    signal::{self, unix::SignalKind},
    sync::mpsc,
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tower_http::cors::{Any, CorsLayer};
use tracing::trace;

use crate::message::Message;

pub struct NodeLauncher {
    pub node: Arc<Mutex<Node>>,
    pub config: NodeConfig,
    pub rpc_module: RpcModule<Arc<Mutex<Node>>>,
    pub inbound_message_sender: UnboundedSender<(PeerId, Message)>,
    pub inbound_message_receiver: UnboundedReceiverStream<(PeerId, Message)>,
    pub reset_timeout_receiver: UnboundedReceiverStream<()>,
    node_launched: bool,
}

impl NodeLauncher {
    pub async fn new(
        secret_key: SecretKey,
        config: NodeConfig,
        outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
    ) -> Result<Self> {
        let (inbound_message_sender, inbound_message_receiver) = mpsc::unbounded_channel();
        let inbound_message_receiver = UnboundedReceiverStream::new(inbound_message_receiver);
        let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
        let reset_timeout_receiver = UnboundedReceiverStream::new(reset_timeout_receiver);

        let node = Node::new(
            config.clone(),
            secret_key,
            outbound_message_sender.clone(),
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
            let middleware = tower::ServiceBuilder::new().layer(cors);
            let port = config.json_rpc_port;
            let server = jsonrpsee::server::ServerBuilder::new()
                .set_middleware(middleware)
                .build((Ipv4Addr::UNSPECIFIED, port))
                .await?;
            let handle = server.start(rpc_module.clone())?;
            let _ = tokio::spawn(handle.stopped());
        }

        Ok(Self {
            node,
            rpc_module,
            inbound_message_sender,
            inbound_message_receiver,
            reset_timeout_receiver,
            node_launched: false,
            config,
        })
    }

    pub fn message_sender(&self) -> UnboundedSender<(PeerId, Message)> {
        self.inbound_message_sender.clone()
    }

    pub async fn start_p2p_node(&mut self) -> Result<()> {
        if self.node_launched {
            return Err(anyhow!("Node already running!"));
        }

        let mut terminate = signal::unix::signal(SignalKind::terminate())?;
        let sleep = time::sleep(self.config.consensus_timeout);
        tokio::pin!(sleep);

        self.node_launched = true;

        loop {
            select! {
                message = self.inbound_message_receiver.next() => {
                    let (source, message) = message.expect("message stream should be infinite");
                    self.node.lock().unwrap().handle_message(source, message).unwrap();
                },
                () = &mut sleep => {
                    trace!("timeout elapsed");
                    self.node.lock().unwrap().handle_timeout().unwrap();
                    sleep.as_mut().reset(Instant::now() + self.config.consensus_timeout);
                },
                r = self.reset_timeout_receiver.next() => {
                    let () = r.expect("reset timeout stream should be infinite");
                    trace!("timeout reset");
                    sleep.as_mut().reset(Instant::now() + self.config.consensus_timeout);
                },
                _ = terminate.recv() => { break; },
                _ = signal::ctrl_c() => { break; },
            }
        }
        Ok(())
    }
}
