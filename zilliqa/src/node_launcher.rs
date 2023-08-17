use jsonrpsee::{server::ServerHandle, RpcModule};
use std::{
    iter,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api,
    cfg::Config,
    crypto::SecretKey,
    networking::{request_response, MessageCodec, MessageProtocol, ProtocolSupport},
    node,
};

use anyhow::{anyhow, Result};
use clap::Parser;
use http::{header, Method};
use libp2p::{
    core::upgrade,
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identify, mdns,
    multiaddr::{Multiaddr, Protocol},
    noise,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Transport,
};

use node::Node;
use tokio::{
    select,
    signal::{self, unix::SignalKind},
    sync::mpsc,
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tower_http::cors::{Any, CorsLayer};
use tracing::*;

use crate::message::Message;

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
    #[clap(long, default_value = "false")]
    no_jsonrpc: bool,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    request_response: request_response::Behaviour<MessageCodec>,
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
}

pub struct NodeLauncher {
    pub node: Arc<Mutex<Node>>,
    pub rpc_module: RpcModule<Arc<Mutex<Node>>>,
    pub secret_key: SecretKey,
    pub peer_id: PeerId,
    pub message_sender: UnboundedSender<(Option<PeerId>, Message)>,
    pub message_receiver: UnboundedReceiverStream<(Option<PeerId>, Message)>,
    pub reset_timeout_sender: UnboundedSender<()>,
    pub reset_timeout_receiver: UnboundedReceiverStream<()>,
    rpc_launched: bool,
    node_launched: bool,
    consensus_timeout: Duration,
    bootstrap_address: Option<Multiaddr>,
}

impl NodeLauncher {
    pub fn new(secret_key: SecretKey, config: Config) -> Result<Self> {
        let (message_sender, message_receiver) = mpsc::unbounded_channel();
        let message_receiver = UnboundedReceiverStream::new(message_receiver);
        let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
        let reset_timeout_receiver = UnboundedReceiverStream::new(reset_timeout_receiver);

        let peer_id = PeerId::from(secret_key.to_libp2p_keypair().public());

        let node = Node::new(
            config.clone(),
            secret_key,
            message_sender.clone(),
            reset_timeout_sender.clone(),
        )?;
        let node = Arc::new(Mutex::new(node));

        let rpc_module = api::rpc_module(Arc::clone(&node));

        Ok(Self {
            node,
            rpc_module,
            secret_key,
            peer_id,
            message_sender,
            message_receiver,
            reset_timeout_sender,
            reset_timeout_receiver,
            rpc_launched: false,
            node_launched: false,
            consensus_timeout: config.consensus_timeout,
            bootstrap_address: config.bootstrap_address,
        })
    }

    pub fn get_node_handle(&self) -> Arc<Mutex<Node>> {
        self.node.clone()
    }

    pub fn get_rpc_server_handle(&self) -> RpcModule<Arc<Mutex<Node>>> {
        self.rpc_module.clone()
    }

    pub fn get_message_sender_handle(&self) -> UnboundedSender<(Option<PeerId>, Message)> {
        self.message_sender.clone()
    }

    pub fn get_reset_timeout_sender_handle(&self) -> UnboundedSender<()> {
        self.reset_timeout_sender.clone()
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
        let port = self.node.lock().unwrap().config.json_rpc_port;
        let server = jsonrpsee::server::ServerBuilder::new()
            .set_middleware(middleware)
            .build((Ipv4Addr::UNSPECIFIED, port))
            .await?;
        let handle = server.start(self.rpc_module.clone());
        self.rpc_launched = true;
        Ok(handle)
    }

    pub async fn start_p2p_node(&mut self, p2p_port: u16) -> Result<()> {
        if self.node_launched {
            return Err(anyhow!("Node already running!"));
        }

        let key_pair = self.secret_key.to_libp2p_keypair();
        let peer_id = PeerId::from(key_pair.public());
        info!(%peer_id);

        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&key_pair)?)
            .multiplex(yamux::Config::default())
            .boxed();

        let behaviour = Behaviour {
            // TODO: Consider replacing with [request_response::json::Behaviour].
            request_response: request_response::Behaviour::with_codec(
                MessageCodec,
                iter::once((MessageProtocol, ProtocolSupport::Full)),
                Default::default(),
            ),
            gossipsub: gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key_pair.clone()),
                gossipsub::ConfigBuilder::default()
                    .max_transmit_size(524288)
                    .build()
                    .map_err(|e| anyhow!(e))?,
            )
            .map_err(|e| anyhow!(e))?,
            mdns: mdns::Behaviour::new(Default::default(), peer_id)?,
            identify: identify::Behaviour::new(identify::Config::new(
                "/ipfs/id/1.0.0".to_owned(),
                key_pair.public(),
            )),
        };

        let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, peer_id).build();

        let mut addr: Multiaddr = "/ip4/0.0.0.0".parse().unwrap();

        addr.push(Protocol::Tcp(p2p_port));

        swarm.listen_on(addr)?;

        if let Some(bootstrap_address) = &self.bootstrap_address {
            swarm.dial(
                DialOpts::unknown_peer_id()
                    .address(bootstrap_address.clone())
                    .build(),
            )?;
        }

        let topic = IdentTopic::new("topic");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        let mut terminate = signal::unix::signal(SignalKind::terminate())?;
        let sleep = time::sleep(self.consensus_timeout);
        tokio::pin!(sleep);

        self.node_launched = true;

        let mut joined = false;

        loop {
            select! {
                event = swarm.next() => match event.expect("swarm stream should be infinite") {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(%address, "started listening");
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer, _) in list {
                            info!(%peer, "adding peer");
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer, _) in list {
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { info: identify::Info { observed_addr, .. }, .. })) => {
                        // Mark the address observed for us by the external peer as confirmed.
                        // TODO: We shouldn't trust this, instead we should confirm our own address manually or using
                        // `libp2p-autonat`.
                        swarm.add_external_address(observed_addr);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message{
                        message: gossipsub::Message {
                            source,
                            data, ..
                        }, ..
                    })) => {
                        let source = source.expect("message should have a source");
                        let message = serde_json::from_slice::<Message>(&data).unwrap();
                        let message_type = message.name();
                        let to = self.peer_id;
                        debug!(%source, %to, message_type, "broadcast recieved");
                        self.node.lock().unwrap().handle_message(source, message).unwrap();
                    }

                    SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(request_response::Event::Message { message, peer })) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                let to = self.peer_id;
                                let message_type = request.name();
                                debug!(%peer, %to, message_type, "message received");

                                self.node.lock().unwrap().handle_message(peer, request).unwrap();

                                let _ = swarm.behaviour_mut().request_response.send_response(channel, Message::RequestResponse);
                            }
                            request_response::Message::Response { .. } => {}
                        }
                    }
                    _ => {},
                },
                message = self.message_receiver.next() => {
                    let (dest, message) = message.expect("message stream should be infinite");
                    let message_type = message.name();
                    let data = serde_json::to_vec(&message).unwrap();
                    let from = self.peer_id;

                    match dest {
                        Some(dest) => {
                            trace!(%dest, message_type, "sending direct message");
                            let _ = swarm.behaviour_mut().request_response.send_request(&dest, message);
                        },
                        None => {
                            trace!(message_type, "sending gossip message");
                            match swarm.behaviour_mut().gossipsub.publish(topic.hash(), data)  {
                                Ok(_) => {},
                                Err(e) => {
                                    error!(%e, "failed to publish message");
                                }
                            }
                            // Also broadcast the message to ourselves.
                            self.node.lock().unwrap().handle_message(from, message).unwrap();
                        },
                    }
                },
                () = &mut sleep => {
                    trace!("timeout elapsed");
                    if !joined {
                        self.message_sender.send((None, Message::JoinCommittee(self.secret_key.node_public_key()))).unwrap();
                        joined = true;
                    } else {
                        self.node.lock().unwrap().handle_timeout().unwrap();
                    }
                    sleep.as_mut().reset(Instant::now() + self.consensus_timeout);
                },
                r = self.reset_timeout_receiver.next() => {
                    let () = r.expect("reset timeout stream should be infinite");
                    trace!("timeout reset");
                    sleep.as_mut().reset(Instant::now() + self.consensus_timeout);
                },
                _ = terminate.recv() => { break; },
                _ = signal::ctrl_c() => { break; },
            }
        }
        Ok(())
    }
}
