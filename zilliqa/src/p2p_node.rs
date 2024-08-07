//! A node in the Zilliqa P2P network. May coordinate multiple shard nodes.

use std::{collections::HashMap, iter, time::Duration};

use anyhow::{anyhow, Result};
use libp2p::{
    core::upgrade,
    dns,
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity, TopicHash},
    identify,
    kad::{self, store::MemoryStore},
    mdns,
    multiaddr::{Multiaddr, Protocol},
    noise,
    request_response::{self, OutboundFailure, ProtocolSupport},
    swarm::{self, dial_opts::DialOpts, NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, StreamProtocol, Swarm, Transport,
};
use tokio::{
    select,
    signal::{self, unix::SignalKind},
    sync::{mpsc, mpsc::UnboundedSender},
    task::JoinSet,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;

use crate::{
    cfg::{Config, ConsensusConfig, NodeConfig},
    crypto::SecretKey,
    db,
    message::{ExternalMessage, InternalMessage},
    node::{OutgoingMessageFailure, RequestId},
    node_launcher::NodeLauncher,
};

/// Messages are a tuple of the destination shard ID and the actual message.
type DirectMessage = (u64, ExternalMessage);

#[derive(NetworkBehaviour)]
struct Behaviour {
    request_response: request_response::cbor::Behaviour<DirectMessage, DirectMessage>,
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
}

/// Messages circulating over the p2p network.
/// (destination, shard_id, message)
pub type OutboundMessageTuple = (Option<(PeerId, RequestId)>, u64, ExternalMessage);

/// Messages passed between local shard nodes.
/// (source_shard, destination_shard, message)
pub type LocalMessageTuple = (u64, u64, InternalMessage);

struct NodeInputChannels {
    external: UnboundedSender<(PeerId, Result<ExternalMessage, OutgoingMessageFailure>)>,
    internal: UnboundedSender<(u64, InternalMessage)>,
}

pub struct P2pNode {
    shard_nodes: HashMap<TopicHash, NodeInputChannels>,
    shard_threads: JoinSet<Result<()>>,
    task_threads: JoinSet<Result<()>>,
    secret_key: SecretKey,
    config: Config,
    peer_id: PeerId,
    swarm: Swarm<Behaviour>,
    /// Shard nodes get a copy of these senders to propagate messages.
    outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
    local_message_sender: UnboundedSender<LocalMessageTuple>,
    /// The p2p node keeps a handle to these receivers, to obtain messages from shards and propagate
    /// them as necessary.
    outbound_message_receiver: UnboundedReceiverStream<OutboundMessageTuple>,
    local_message_receiver: UnboundedReceiverStream<LocalMessageTuple>,
    // Map of pending direct requests. Maps the libp2p request ID to our request ID.
    pending_requests: HashMap<request_response::OutboundRequestId, (u64, RequestId)>,
}

impl P2pNode {
    pub fn new(secret_key: SecretKey, config: Config) -> Result<Self> {
        let (outbound_message_sender, outbound_message_receiver) = mpsc::unbounded_channel();
        let outbound_message_receiver = UnboundedReceiverStream::new(outbound_message_receiver);

        let (local_message_sender, local_message_receiver) = mpsc::unbounded_channel();
        let local_message_receiver = UnboundedReceiverStream::new(local_message_receiver);

        let key_pair = secret_key.to_libp2p_keypair();
        let peer_id = PeerId::from(key_pair.public());
        info!(%peer_id);

        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&key_pair)?)
            .multiplex(yamux::Config::default())
            .boxed();
        let transport = dns::tokio::Transport::system(transport)?.boxed();

        let behaviour = Behaviour {
            request_response: request_response::cbor::Behaviour::new(
                iter::once((StreamProtocol::new("/zq2-message/1"), ProtocolSupport::Full)),
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
            kademlia: kad::Behaviour::new(peer_id, MemoryStore::new(peer_id)),
        };

        let swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            swarm::Config::with_tokio_executor(),
        );

        Ok(Self {
            shard_nodes: HashMap::new(),
            peer_id,
            secret_key,
            config,
            swarm,
            shard_threads: JoinSet::new(),
            task_threads: JoinSet::new(),
            outbound_message_sender,
            local_message_sender,
            outbound_message_receiver,
            local_message_receiver,
            pending_requests: HashMap::new(),
        })
    }

    pub fn shard_id_to_topic(shard_id: u64) -> IdentTopic {
        IdentTopic::new(shard_id.to_string())
    }

    /// Temporary method until light nodes are implemented, which will allow
    /// connecting to the other shard and obtaining consensus parameters.
    /// For now, we copy the (presumably main shard's) existing config and use it
    /// as a default to construct a child shard.
    fn generate_child_config(parent: &NodeConfig, shard_id: u64) -> NodeConfig {
        let parent = parent.clone();
        NodeConfig {
            json_rpc_port: parent.json_rpc_port + 1,
            eth_chain_id: shard_id,
            consensus: ConsensusConfig {
                is_main: false,
                main_shard_id: Some(parent.eth_chain_id),
                ..parent.consensus
            },
            ..parent
        }
    }

    pub async fn add_shard_node(&mut self, config: NodeConfig) -> Result<()> {
        let topic = Self::shard_id_to_topic(config.eth_chain_id);
        if self.shard_nodes.contains_key(&topic.hash()) {
            info!("LaunchShard message received for a shard we're already running. Ignoring...");
            return Ok(());
        }
        let mut node = NodeLauncher::new(
            self.secret_key,
            config,
            self.outbound_message_sender.clone(),
            self.local_message_sender.clone(),
        )
        .await?;
        self.shard_nodes.insert(
            topic.hash(),
            NodeInputChannels {
                external: node.message_input(),
                internal: node.local_message_input(),
            },
        );
        self.shard_threads
            .spawn(async move { node.start_shard_node().await });
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        Ok(())
    }

    fn forward_external_message_to_node(
        &self,
        topic_hash: &TopicHash,
        source: PeerId,
        message: Result<ExternalMessage, OutgoingMessageFailure>,
    ) -> Result<()> {
        match self.shard_nodes.get(topic_hash) {
            Some(inbound_message_sender) => {
                inbound_message_sender.external.send((source, message))?
            }
            None => warn!(
                ?topic_hash,
                ?source,
                ?message,
                "Message received for unknown shard/topic"
            ),
        };
        Ok(())
    }

    fn forward_local_message_to_shard(
        &self,
        topic_hash: &TopicHash,
        source_shard: u64,
        message: InternalMessage,
    ) -> Result<()> {
        match self.shard_nodes.get(topic_hash) {
            Some(inbound_message_sender) => inbound_message_sender
                .internal
                .send((source_shard, message))?,
            None => {
                warn!(
                    ?topic_hash,
                    ?source_shard,
                    ?message,
                    "Message received for unknown shard/topic"
                )
            }
        };
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        let mut addr: Multiaddr = "/ip4/0.0.0.0".parse().unwrap();
        addr.push(Protocol::Tcp(self.config.p2p_port));

        self.swarm.listen_on(addr)?;
        if let Some(external_address) = &self.config.external_address {
            self.swarm.add_external_address(external_address.clone());
        }

        if let Some((peer, address)) = &self.config.bootstrap_address {
            self.swarm.dial(
                DialOpts::peer_id(*peer)
                    .addresses(vec![address.clone()])
                    .build(),
            )?;
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer, address.clone());
        }

        // Bootstrap Kademlia every 5 minutes to discover new nodes.
        let mut bootstrap = tokio::time::interval(Duration::from_secs(5 * 60));

        let mut terminate = signal::unix::signal(SignalKind::terminate())?;

        loop {
            select! {
                event = self.swarm.next() => {
                    let event = event.expect("swarm stream should be infinite");
                    debug!(?event, "swarm event");
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(%address, "started listening");
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, addr) in list {
                                info!(%peer_id, %addr, "discovered peer via mDNS");
                                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, addr) in list {
                                self.swarm.behaviour_mut().kademlia.remove_address(&peer_id, &addr);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { info: identify::Info { observed_addr, listen_addrs, .. }, peer_id })) => {
                            for addr in listen_addrs {
                                // If the node is advertising a non-global address, ignore it.
                                let is_non_global = addr.iter().any(|p| match p {
                                    Protocol::Ip4(addr) => addr.is_loopback() || addr.is_private(),
                                    Protocol::Ip6(addr) => addr.is_loopback(),
                                    _ => false,
                                });
                                if is_non_global {
                                    continue;
                                }

                                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            }
                            // Mark the address observed for us by the external peer as confirmed. Only do this if our
                            // configuration hasn't already told us an external address.
                            if self.config.external_address.is_none() {
                                self.swarm.add_external_address(observed_addr);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message{
                            message: gossipsub::Message {
                                source,
                                data,
                                topic: topic_hash, ..
                            }, ..
                        })) => {
                            let source = source.expect("message should have a source");
                            let message = cbor4ii::serde::from_slice::<ExternalMessage>(&data).unwrap();
                            let to = self.peer_id;
                            debug!(%source, %to, %message, "broadcast recieved");
                            self.forward_external_message_to_node(&topic_hash, source, Ok(message))?;
                        }

                        SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(request_response::Event::Message { message, peer: source })) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => {
                                    let to = self.peer_id;
                                    let (shard_id, external_message) = request;
                                    debug!(%source, %to, %external_message, "message received");
                                    let topic = Self::shard_id_to_topic(shard_id);
                                    self.forward_external_message_to_node(&topic.hash(), source, Ok(external_message))?;
                                    let _ = self.swarm.behaviour_mut().request_response.send_response(channel, (shard_id, ExternalMessage::RequestResponse));
                                }
                                request_response::Message::Response { request_id, .. } => {
                                    self.pending_requests.remove(&request_id);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(request_response::Event::OutboundFailure { peer, request_id, error })) => {
                            if let OutboundFailure::DialFailure = error {
                                // We failed to send a message to a peer. The likely reason is that we don't know their
                                // address. Someone else in the network must know it, because we learnt their peer ID.
                                // Therefore, we can attempt to learn their address by triggering a Kademlia bootstrap.
                                let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                            }


                            if let Some((shard_id, request_id)) = self.pending_requests.remove(&request_id) {
                                let error = OutgoingMessageFailure { peer, request_id, error };
                                self.forward_external_message_to_node(&Self::shard_id_to_topic(shard_id).hash(), peer, Err(error))?;
                            } else {
                                return Err(anyhow!("request without id failed"));
                            }
                        }
                        _ => {},
                    }
                },
                _ = bootstrap.tick() => {
                    let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                }
                message = self.local_message_receiver.next() => {
                    let (source, destination, message) = message.expect("message stream should be infinite");
                    match message {
                        InternalMessage::LaunchShard(shard_id) => {
                            let shard_config = self.config.nodes
                                .iter()
                                .find(|shard_config| shard_config.eth_chain_id == shard_id)
                                .cloned()
                                .unwrap_or_else(
                                    || Self::generate_child_config(self.config.nodes.first().unwrap(), shard_id));
                            self.add_shard_node(shard_config.clone()).await?;
                        },
                        InternalMessage::LaunchLink(_) | InternalMessage::IntershardCall(_) => {
                            self.forward_local_message_to_shard(&Self::shard_id_to_topic(destination).hash(), source, message)?;
                        }
                        InternalMessage::ExportBlockCheckpoint(block, parent, trie_storage, path) => {
                            self.task_threads.spawn(async move { db::checkpoint_block_with_state(&block, &parent, trie_storage, source, path) });
                        }
                    }
                },
                message = self.outbound_message_receiver.next() => {
                    let (dest, shard_id, message) = message.expect("message stream should be infinite");
                    let data = cbor4ii::serde::to_vec(Vec::new(), &message).unwrap();
                    let from = self.peer_id;

                    let topic = Self::shard_id_to_topic(shard_id);

                    match dest {
                        Some((dest, request_id)) => {
                            debug!(%from, %dest, %message, "sending direct message");
                            if from == dest {
                                self.forward_external_message_to_node(&topic.hash(), from, Ok(message))?;
                            } else {
                                let libp2p_request_id = self.swarm.behaviour_mut().request_response.send_request(&dest, (shard_id, message));
                                self.pending_requests.insert(libp2p_request_id, (shard_id, request_id));
                            }
                        },
                        None => {
                            debug!(%from, %message, "broadcasting");
                            match self.swarm.behaviour_mut().gossipsub.publish(topic.hash(), data)  {
                                Ok(_) => {},
                                Err(e) => {
                                    trace!(%e, "failed to publish message");
                                }
                            }
                            // Also broadcast the message to ourselves.
                            self.forward_external_message_to_node(&topic.hash(), from, Ok(message))?;
                        },
                    }
                },
                Some(res) = self.task_threads.join_next() => {
                    if let Err(e) = res {
                        // One-shot task (i.e. checkpoint export) failed. Log it and carry on.
                        error!(%e);
                    }
                }
                Some(res) = self.shard_threads.join_next() => {
                    if let Err(e) = res {
                        // Currently, abort everything should a single shard fail.
                        error!(%e);
                        break;
                    }
                }
                _ = terminate.recv() => {
                    self.shard_threads.shutdown().await;
                    break;
                },
                _ = signal::ctrl_c() => {
                    self.shard_threads.shutdown().await;
                    break;
                },
            }
        }
        Ok(())
    }
}
