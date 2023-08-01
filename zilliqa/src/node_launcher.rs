use jsonrpsee::{server::ServerHandle, RpcModule};
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{api, cfg::NodeConfig, crypto::SecretKey, node};

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
use tracing::{debug, info, trace};

use crate::message::Message;

pub struct NodeLauncher {
    pub node: Arc<Mutex<Node>>,
    pub config: NodeConfig,
    pub rpc_module: RpcModule<Arc<Mutex<Node>>>,
    pub secret_key: SecretKey,
    pub peer_id: PeerId,
    pub inbound_message_sender: UnboundedSender<(Option<PeerId>, Message)>,
    pub inbound_message_receiver: UnboundedReceiverStream<(Option<PeerId>, Message)>,
    pub reset_timeout_sender: UnboundedSender<()>,
    pub reset_timeout_receiver: UnboundedReceiverStream<()>,
    outbound_message_sender: UnboundedSender<(Option<PeerId>, Message)>,
    rpc_launched: bool,
    node_launched: bool,
}

impl NodeLauncher {
    pub fn new(
        secret_key: SecretKey,
        config: NodeConfig,
        outbound_message_sender: UnboundedSender<(Option<PeerId>, Message)>,
    ) -> Result<Self> {
        let (inbound_message_sender, inbound_message_receiver) = mpsc::unbounded_channel();
        let inbound_message_receiver = UnboundedReceiverStream::new(inbound_message_receiver);
        let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
        let reset_timeout_receiver = UnboundedReceiverStream::new(reset_timeout_receiver);

        let peer_id = PeerId::from(secret_key.to_libp2p_keypair().public());

        let node = Node::new(
            config.clone(),
            secret_key,
            inbound_message_sender.clone(),
            reset_timeout_sender.clone(),
        )?;
        let node = Arc::new(Mutex::new(node));

        let rpc_module = api::rpc_module(Arc::clone(&node));

        Ok(Self {
            node,
            rpc_module,
            secret_key,
            peer_id,
            inbound_message_sender,
            inbound_message_receiver,
            reset_timeout_sender,
            reset_timeout_receiver,
            outbound_message_sender,
            rpc_launched: false,
            node_launched: false,
            config,
        })
    }

    pub fn message_sender(&self) -> UnboundedSender<(Option<PeerId>, Message)> {
        self.inbound_message_sender.clone()
    }

    pub async fn launch_rpc_server(&mut self) -> Result<ServerHandle> {
        if self.rpc_launched {
            return Err(anyhow!("RPC server already running!"));
        }
        trace!("Launching JSON-RPC server");
        // Construct the JSON-RPC API server. We inject a [CorsLayer] to ensure web browsers can call our API directly.
        let cors = CorsLayer::new()
            .allow_methods(Method::POST)
            .allow_origin(Any)
            .allow_headers([header::CONTENT_TYPE]);
        let middleware = tower::ServiceBuilder::new().layer(cors);
        let port = self.config.json_rpc_port;
        let server = jsonrpsee::server::ServerBuilder::new()
            .set_middleware(middleware)
            .build((Ipv4Addr::UNSPECIFIED, port))
            .await?;
        Ok(server.start(self.rpc_module.clone()).map(|res| {
            self.rpc_launched = true;
            res
        })?)
    }

    pub async fn start_p2p_node(&mut self) -> Result<()> {
        if self.node_launched {
            return Err(anyhow!("Node already running!"));
        }

        let key_pair = self.secret_key.to_libp2p_keypair();
        let peer_id = PeerId::from(key_pair.public());
        info!(%peer_id);

        let mut terminate = signal::unix::signal(SignalKind::terminate())?;
        let sleep = time::sleep(self.config.consensus_timeout);
        tokio::pin!(sleep);

        self.node_launched = true;

        loop {
            select! {
                message = self.inbound_message_receiver.next() => {
                    let (dest, message) = message.expect("message stream should be infinite");
                    let message_type = message.name();
                    let data = serde_json::to_vec(&message).unwrap();

                    match dest {
                        Some(dest) => {
                            debug!(%dest, message_type, "sending direct message");
                            // TODO: send message over to p2p node
                            // let _ = swarm.behaviour_mut().request_response.send_request(&dest, message);
                        },
                        None => {
                            debug!(message_type, "sending gossip message");
                            // TODO: send message over to p2p node
                            // match swarm.behaviour_mut().gossipsub.publish(topic.hash(), data)  {
                            //     Ok(_) => {},
                            //     Err(e) => {
                            //         error!(%e, "failed to publish message");
                            //     }
                            // }
                        },
                    }
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
