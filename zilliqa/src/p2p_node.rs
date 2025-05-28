//! A node in the Zilliqa P2P network. May coordinate multiple shard nodes.

use std::{
    collections::HashMap,
    iter,
    sync::{
        Arc,
        atomic::{AtomicPtr, AtomicUsize},
    },
    time::Duration,
};

use anyhow::{Result, anyhow};
use cfg_if::cfg_if;
use itertools::Itertools;
use libp2p::{
    PeerId, StreamProtocol, Swarm, autonat,
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity, TopicHash},
    identify,
    kad::{self, store::MemoryStore},
    multiaddr::{Multiaddr, Protocol},
    noise,
    request_response::{self, OutboundFailure, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tokio::{
    select,
    signal::{self, unix::SignalKind},
    sync::mpsc::{self, UnboundedSender, error::SendError},
    task::JoinSet,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;

use crate::{
    cfg::{Config, ConsensusConfig, NodeConfig},
    crypto::SecretKey,
    db,
    message::{ExternalMessage, GossipSubTopic, InternalMessage},
    node::{OutgoingMessageFailure, RequestId},
    node_launcher::{NodeInputChannels, NodeLauncher, ResponseChannel},
    sync::SyncPeers,
};

/// Validator topic is for broadcasts which only apply to validators.
///
/// - Broadcasts are so sent to the public topic (Proposal)
/// - Direct messages are not sent to any topic (Vote, NewView)
/// - Re-sending of NewView is sent to the Validator-only topic
static VALIDATOR_TOPIC_SUFFIX: &str = "-validator";

/// Messages are a tuple of the destination shard ID and the actual message.
type DirectMessage = (u64, ExternalMessage);

#[derive(NetworkBehaviour)]
struct Behaviour {
    request_response: request_response::cbor::Behaviour<DirectMessage, ExternalMessage>,
    gossipsub: gossipsub::Behaviour,
    autonat_client: autonat::v2::client::Behaviour,
    autonat_server: autonat::v2::server::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
}

/// Messages circulating over the p2p network.
/// (destination, shard_id, message)
pub type OutboundMessageTuple = (Option<(PeerId, RequestId)>, u64, ExternalMessage);

/// Messages passed between local shard nodes.
/// (source_shard, destination_shard, message)
pub type LocalMessageTuple = (u64, u64, InternalMessage);

pub struct P2pNode {
    shard_peers: HashMap<u64, Arc<SyncPeers>>,
    shard_nodes: HashMap<u64, NodeInputChannels>,
    shard_threads: JoinSet<Result<()>>,
    task_threads: JoinSet<Result<()>>,
    secret_key: SecretKey,
    config: Config,
    peer_id: PeerId,
    swarm: Swarm<Behaviour>,
    /// Shard nodes get a copy of these senders to propagate messages.
    outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
    local_message_sender: UnboundedSender<LocalMessageTuple>,
    request_responses_sender: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    /// The p2p node keeps a handle to these receivers, to obtain messages from shards and propagate
    /// them as necessary.
    outbound_message_receiver: UnboundedReceiverStream<OutboundMessageTuple>,
    local_message_receiver: UnboundedReceiverStream<LocalMessageTuple>,
    request_responses_receiver: UnboundedReceiverStream<(ResponseChannel, ExternalMessage)>,
    /// Map of pending direct requests. Maps the libp2p request ID to our request ID.
    pending_requests: HashMap<request_response::OutboundRequestId, (u64, RequestId)>,
    // Count of current peers for API
    peer_num: Arc<AtomicUsize>,
    swarm_peers: Arc<AtomicPtr<Vec<PeerId>>>,
}

impl P2pNode {
    pub fn new(secret_key: SecretKey, config: Config) -> Result<Self> {
        let (outbound_message_sender, outbound_message_receiver) = mpsc::unbounded_channel();
        let outbound_message_receiver = UnboundedReceiverStream::new(outbound_message_receiver);

        let (local_message_sender, local_message_receiver) = mpsc::unbounded_channel();
        let local_message_receiver = UnboundedReceiverStream::new(local_message_receiver);

        let (request_responses_sender, request_responses_receiver) = mpsc::unbounded_channel();
        let request_responses_receiver = UnboundedReceiverStream::new(request_responses_receiver);

        let key_pair = secret_key.to_libp2p_keypair();
        let peer_id = PeerId::from(key_pair.public());
        info!(%peer_id);

        let swarm = libp2p::SwarmBuilder::with_existing_identity(key_pair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|key_pair| {
                Ok(Behaviour {
                    request_response: request_response::cbor::Behaviour::new(
                        iter::once((StreamProtocol::new("/zq2-message/1"), ProtocolSupport::Full)),
                        request_response::Config::default()
                            // This is a temporary patch to prevent long-running Scilla executions causing nodes to Timeout - https://github.com/Zilliqa/zq2/issues/2667
                            .with_request_timeout(Duration::from_secs(60)),
                    ),
                    gossipsub: gossipsub::Behaviour::new(
                        MessageAuthenticity::Signed(key_pair.clone()),
                        gossipsub::ConfigBuilder::default()
                            // 1MB is sufficient to accommodate proposal with 4000 simple transfers (block gas limit)
                            .max_transmit_size(1024 * 1024)
                            // Increase the duplicate cache time to reduce the likelihood of delayed messages being
                            // mistakenly re-propagated and flooding the network.
                            .duplicate_cache_time(Duration::from_secs(3600))
                            // Increase the queue duration to reduce the likelihood of dropped messages.
                            // https://github.com/Zilliqa/zq2/issues/2823
                            .publish_queue_duration(Duration::from_secs(50))
                            .forward_queue_duration(Duration::from_secs(30)) // might be helpful too
                            .build()
                            .map_err(|e| anyhow!(e))?,
                    )
                    .map_err(|e| anyhow!(e))?,
                    autonat_client: autonat::v2::client::Behaviour::default(),
                    autonat_server: autonat::v2::server::Behaviour::default(),
                    kademlia: kad::Behaviour::new(peer_id, MemoryStore::new(peer_id)),
                    identify: identify::Behaviour::new(
                        identify::Config::new("zilliqa/1.0.0".into(), key_pair.public())
                            .with_hide_listen_addrs(true)
                            .with_push_listen_addr_updates(true),
                    ),
                })
            })?
            // Set the idle connection timeout to 10 seconds. Some protocols (such as autonat) rely on using a
            // connection shortly after an event has been emitted from the `Swarm`, but don't use it immediately
            // meaning the connection is immediately closed before the protocol can use it. libp2p may change the
            // default in the future to 10 seconds too (https://github.com/libp2p/rust-libp2p/pull/4967).
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();

        Ok(Self {
            shard_peers: HashMap::new(),
            shard_nodes: HashMap::new(),
            peer_id,
            secret_key,
            config,
            swarm,
            shard_threads: JoinSet::new(),
            task_threads: JoinSet::new(),
            outbound_message_sender,
            local_message_sender,
            request_responses_sender,
            outbound_message_receiver,
            local_message_receiver,
            request_responses_receiver,
            pending_requests: HashMap::new(),
            peer_num: Arc::new(AtomicUsize::new(0)),
            swarm_peers: Arc::new(AtomicPtr::new(Box::into_raw(Box::new(vec![])))),
        })
    }

    pub fn shard_id_to_topic(shard_id: u64, message: Option<&ExternalMessage>) -> IdentTopic {
        match message {
            Some(ExternalMessage::NewView(_)) => Self::validator_topic(shard_id),
            _ => IdentTopic::new(shard_id.to_string()),
        }
    }

    pub fn shard_id_from_topic_hash(topic_hash: &TopicHash) -> Result<u64> {
        Ok(topic_hash
            .clone()
            .into_string()
            .split("-")
            .collect::<Vec<_>>()[0]
            .parse::<u64>()?)
    }

    pub fn validator_topic(shard_id: u64) -> IdentTopic {
        IdentTopic::new(shard_id.to_string() + VALIDATOR_TOPIC_SUFFIX)
    }

    /// Temporary method until light nodes are implemented, which will allow
    /// connecting to the other shard and obtaining consensus parameters.
    /// For now, we copy the (presumably main shard's) existing config and use it
    /// as a default to construct a child shard.
    fn generate_child_config(parent: &NodeConfig, shard_id: u64) -> NodeConfig {
        let parent = parent.clone();
        NodeConfig {
            api_servers: vec![],
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
        let shard_id = config.eth_chain_id;
        if self.shard_nodes.contains_key(&shard_id) {
            info!("LaunchShard message received for a shard we're already running. Ignoring...");
            return Ok(());
        }
        let (mut node, input_channels, peers) = NodeLauncher::new(
            self.secret_key,
            config,
            self.outbound_message_sender.clone(),
            self.local_message_sender.clone(),
            self.request_responses_sender.clone(),
            self.peer_num.clone(),
            self.swarm_peers.clone(),
        )
        .await?;
        self.shard_peers.insert(shard_id, peers);
        self.shard_nodes.insert(shard_id, input_channels);
        self.shard_threads
            .spawn(async move { node.start_shard_node().await });
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&Self::shard_id_to_topic(shard_id, None))?;
        // subscribe to validator topic by default. Unsubscribe later if we find that we are not in the committee
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&Self::validator_topic(shard_id))?;
        Ok(())
    }

    fn send_to<T: Send + Sync + 'static>(
        &self,
        topic_hash: &TopicHash,
        sender: impl FnOnce(&NodeInputChannels) -> Result<(), SendError<T>>,
    ) -> Result<()> {
        let Some(channels) = self
            .shard_nodes
            .get(&Self::shard_id_from_topic_hash(topic_hash)?)
        else {
            warn!(?topic_hash, "message received for unknown shard or topic");
            return Ok(());
        };
        Ok(sender(channels)?)
    }

    pub async fn start(&mut self) -> Result<()> {
        self.swarm.listen_on(
            Multiaddr::empty()
                .with(Protocol::Ip4(std::net::Ipv4Addr::UNSPECIFIED))
                .with(Protocol::Tcp(self.config.p2p_port)),
        )?;

        if let Some(external_address) = &self.config.external_address {
            self.swarm.add_external_address(external_address.clone());
        }

        // if we are a bootstrap, add our external address, which allows us to switch to kademlia SERVER mode.
        for (peer, address) in &self.config.bootstrap_address.0 {
            if self.swarm.local_peer_id() == peer {
                self.swarm.add_external_address(address.clone());
            }
        }

        let mut terminate = signal::unix::signal(SignalKind::terminate())?;

        loop {
            select! {
                event = self.swarm.next() => {
                    let event = event.expect("swarm stream should be infinite");
                    debug!(?event, "swarm event");
                    match event {
                        SwarmEvent::ConnectionClosed{..} |
                        SwarmEvent::ConnectionEstablished{..} => {
                            // update peers when new peer connects/disconnects
                            let new_peers = Box::into_raw(Box::new(self.swarm.connected_peers().cloned().collect_vec()));
                            let old_ptr = self.swarm_peers.swap(new_peers, std::sync::atomic::Ordering::Relaxed);
                            unsafe {
                                let _ = Box::from_raw(old_ptr); // previous vec will be dropped here
                            }
                        }
                        // only dial after we have a listen address, to reuse port
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(%address, "P2P swarm listening on");
                            for (peer, address) in &self.config.bootstrap_address.0 {
                                if self.swarm.local_peer_id() != peer {
                                    self.swarm.dial(address.clone())?;
                                }
                            }
                        }
                        // this is necessary - https://docs.rs/libp2p-kad/latest/libp2p_kad/#important-discrepancies
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            // will only be true if peer is publicly reachable i.e. SERVER mode.
                            let is_kad = info.protocols.iter().any(|p| *p == kad::PROTOCOL_NAME);
                            for addr in info.listen_addrs {
                                self.swarm.add_peer_address(peer_id, addr.clone());
                                if is_kad {
                                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                }
                            }
                        }
                        // Add/Remove peers to/from the shard peer list used in syncing.
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                            if let Some(peers) = self.shard_peers.get(&Self::shard_id_from_topic_hash(&topic)?) {
                                peers.add_peer(peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic })) => {
                            if let Some(peers) = self.shard_peers.get(&Self::shard_id_from_topic_hash(&topic)?) {
                                peers.remove_peer(peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message{
                            message_id: msg_id,
                            message: gossipsub::Message {
                                source,
                                data,
                                topic: topic_hash, ..
                            }, ..
                        })) => {
                            let source = source.expect("message should have a source");
                            let message = match cbor4ii::serde::from_slice::<ExternalMessage>(&data) {
                                Ok(m) => m,
                                Err(e) => {
                                    let data = hex::encode(&data);
                                    error!(?e, data, "message parsing failed");
                                    continue;
                                }
                            };
                            let to = self.peer_id;
                            debug!(%source, %to, %message, %topic_hash, "broadcast received");

                            match message {
                                // Route broadcasts to speed-up Proposal processing, with faux request-id
                                ExternalMessage::Proposal(_) => {
                                    self.send_to(&topic_hash, |c| c.requests.send((source, msg_id.to_string(), message, ResponseChannel::Local)))?;
                                },
                                _ => {
                                    self.send_to(&topic_hash, |c| c.broadcasts.send((source, message)))?;
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(request_response::Event::Message { message, peer: _source, .. })) => {
                            match message {
                                request_response::Message::Request { request, channel: _channel, request_id: _request_id, .. } => {
                                    let to = self.peer_id;
                                    let (shard_id, _external_message) = request;
                                    debug!(source = %_source, %to, external_message = %_external_message, request_id = %_request_id, "message received");
                                    let _topic = Self::shard_id_to_topic(shard_id, None);
                                    let _id = format!("{}", _request_id);
                                    cfg_if! {
                                        if #[cfg(not(feature = "fake_response_channel"))] {
                                            self.send_to(&_topic.hash(), |c| c.requests.send((_source, _id, _external_message, ResponseChannel::Remote(_channel))))?;
                                        } else {
                                            panic!("fake_response_channel is enabled and you are trying to use a real libp2p network");
                                        }
                                    }
                                }
                                request_response::Message::Response { request_id, response } => {
                                    if let Some((shard_id, _)) = self.pending_requests.remove(&request_id) {
                                        self.send_to(&Self::shard_id_to_topic(shard_id, None).hash(), |c| c.responses.send((_source, response)))?;
                                    } else {
                                        return Err(anyhow!("response to request with no id"));
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(request_response::Event::OutboundFailure { peer, request_id, error, .. })) => {
                            if let OutboundFailure::DialFailure = error {
                                // We failed to send a message to a peer. The likely reason is that we don't know their
                                // address. Someone else in the network must know it, because we learnt their peer ID.
                                // Therefore, we can attempt to learn their address by triggering a Kademlia bootstrap.
                                let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                            }

                            if let Some((shard_id, request_id)) = self.pending_requests.remove(&request_id) {
                                let error = OutgoingMessageFailure { peer, request_id, error };
                                self.send_to(&Self::shard_id_to_topic(shard_id, None).hash(), |c| c.request_failures.send((peer, error)))?;
                            } else {
                                return Err(anyhow!("request without id failed"));
                            }
                        }
                        _ => {},
                    }
                },
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
                            self.send_to(&Self::shard_id_to_topic(destination, None).hash(), |c| c.local_messages.send((source, message)))?;
                        }
                        InternalMessage::ExportBlockCheckpoint(block, transactions, parent, trie_storage, path) => {
                            self.task_threads.spawn(async move { db::checkpoint_block_with_state(&block, &transactions, &parent, trie_storage, source, path) });
                        }
                        InternalMessage::SubscribeToGossipSubTopic(topic) => {
                            debug!("subscribing to topic {:?}", topic);
                            if let GossipSubTopic::Validator(shard_id) = topic {
                                self.swarm.behaviour_mut().gossipsub.subscribe(&Self::validator_topic(shard_id))?;
                            }
                        }
                        InternalMessage::UnsubscribeFromGossipSubTopic(topic) => {
                            debug!("unsubscribing from topic {:?}", topic);
                            if let GossipSubTopic::Validator(shard_id) = topic {
                                self.swarm.behaviour_mut().gossipsub.unsubscribe(&Self::validator_topic(shard_id));
                            }
                        }
                    }
                },
                message = self.request_responses_receiver.next() => {
                    let (ch, _rs) = message.expect("message stream should be infinite");
                    if let Some(_ch) = ch.into_inner() {
                        cfg_if! {
                            if #[cfg(not(feature = "fake_response_channel"))] {
                                let _ = self.swarm.behaviour_mut().request_response.send_response(_ch, _rs);
                            } else {
                                panic!("fake_response_channel is enabled and you are trying to use a real libp2p network");
                            }
                        }
                    }
                }
                message = self.outbound_message_receiver.next() => {
                    let (dest, shard_id, message) = message.expect("message stream should be infinite");
                    let data = cbor4ii::serde::to_vec(Vec::new(), &message).unwrap();
                    let from = self.peer_id;

                    let topic = Self::shard_id_to_topic(shard_id, Some(&message));

                    match dest {
                        Some((dest, request_id)) => {
                            debug!(%from, %dest, %message, ?request_id, "sending direct message");
                            let id = format!("{:?}", request_id);
                            if from == dest {
                                self.send_to(&topic.hash(), |c| c.requests.send((from, id, message, ResponseChannel::Local)))?;
                            } else {
                                let libp2p_request_id = self.swarm.behaviour_mut().request_response.send_request(&dest, (shard_id, message));
                                self.pending_requests.insert(libp2p_request_id, (shard_id, request_id));
                            }
                        },
                        None => {
                            debug!(%from, %message, %topic, "broadcasting");
                            match self.swarm.behaviour_mut().gossipsub.publish(topic.hash(), data.clone())  {
                                // Also route broadcasts to ourselves, with a faux request-id.
                                Ok(msg_id) => {
                                    match message {
                                        ExternalMessage::Proposal(_) => {
                                            self.send_to(&topic.hash(), |c| c.requests.send((from, msg_id.to_string(), message, ResponseChannel::Local)))?;
                                        }
                                        _ => {
                                            self.send_to(&topic.hash(), |c| c.broadcasts.send((from, message)))?;
                                        }
                                    }
                                },
                                // still publish to self, even if no other peers.
                                Err(gossipsub::PublishError::InsufficientPeers) => {
                                    match message {
                                        ExternalMessage::Proposal(_) => {
                                            self.send_to(&topic.hash(), |c| c.requests.send((from, "(faux-id)".to_string(), message, ResponseChannel::Local)))?;
                                        }
                                        _ => {
                                            self.send_to(&topic.hash(), |c| c.broadcasts.send((from, message)))?;
                                        }
                                    }
                                }
                                Err(e) => {
                                    trace!(%e, "failed to publish message");
                                }
                            }
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
                    unsafe {
                        let _ = Box::from_raw(self.swarm_peers.load(std::sync::atomic::Ordering::Relaxed));
                        // previous vec will be dropped here
                    }
                    break;
                },
                _ = signal::ctrl_c() => {
                    self.shard_threads.shutdown().await;
                    unsafe {
                        let _ = Box::from_raw(self.swarm_peers.load(std::sync::atomic::Ordering::Relaxed));
                        // previous vec will be dropped here
                    }
                    break;
                },
            }
            self.peer_num.store(
                self.swarm.network_info().num_peers(),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(())
    }
}
