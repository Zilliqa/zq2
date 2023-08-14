//! A node in the Zilliqa P2P network. May coordinate multiple shard nodes.

use crate::crypto::NodePublicKey;
use std::{collections::HashMap, iter};
use tokio::{sync::mpsc::UnboundedSender, task::JoinSet};

use crate::{
    cfg::NodeConfig,
    crypto::SecretKey,
    networking::{request_response, MessageCodec, MessageProtocol, ProtocolSupport},
    node_launcher::NodeLauncher,
};

use anyhow::{anyhow, Result};
use libp2p::{
    core::upgrade,
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity, TopicHash},
    identify,
    kad::{
        store::MemoryStore, GetRecordOk, Kademlia, KademliaEvent, PeerRecord, QueryResult, Quorum,
        Record,
    },
    mdns,
    multiaddr::{Multiaddr, Protocol},
    multihash::Multihash,
    noise,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Swarm, Transport,
};

use tokio::{
    select,
    signal::{self, unix::SignalKind},
    sync::mpsc,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, info, warn};

use crate::message::{ExternalMessage, InternalMessage, Message};

#[derive(NetworkBehaviour)]
struct Behaviour {
    request_response: request_response::Behaviour<MessageCodec>,
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    kademlia: Kademlia<MemoryStore>,
    identify: identify::Behaviour,
}

/// (destination, shard_id, message)
pub type OutboundMessageTuple = (Option<PeerId>, u64, Message);

pub struct P2pNode {
    shard_nodes: HashMap<TopicHash, UnboundedSender<(PeerId, Message)>>,
    shard_threads: JoinSet<Result<()>>,
    secret_key: SecretKey,
    peer_id: PeerId,
    p2p_port: u16,
    swarm: Swarm<Behaviour>,
    bootstrap_address: Option<Multiaddr>,
    /// Shard nodes get a copy of a handle to this sender, to propagate messages to the p2p network.
    outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
    /// The p2p node keeps a handle to this receiver, to obtain messages from shards and propagate
    /// them to the p2p network.
    outbound_message_receiver: UnboundedReceiverStream<OutboundMessageTuple>,
}

impl P2pNode {
    pub fn new(
        secret_key: SecretKey,
        p2p_port: u16,
        bootstrap_address: Option<Multiaddr>,
    ) -> Result<Self> {
        let (outbound_message_sender, outbound_message_receiver) = mpsc::unbounded_channel();
        let outbound_message_receiver = UnboundedReceiverStream::new(outbound_message_receiver);

        let key_pair = secret_key.to_libp2p_keypair();
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
            kademlia: Kademlia::new(peer_id, MemoryStore::new(peer_id)),
            identify: identify::Behaviour::new(identify::Config::new(
                "/ipfs/id/1.0.0".to_owned(),
                key_pair.public(),
            )),
        };

        let swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, peer_id).build();

        Ok(Self {
            shard_nodes: HashMap::new(),
            secret_key,
            peer_id,
            p2p_port,
            swarm,
            shard_threads: JoinSet::new(),
            bootstrap_address,
            outbound_message_sender,
            outbound_message_receiver,
        })
    }

    pub fn shard_id_to_topic(shard_id: u64) -> IdentTopic {
        IdentTopic::new(shard_id.to_string())
    }

    pub async fn add_shard_node(&mut self, config: NodeConfig) -> Result<()> {
        let topic = Self::shard_id_to_topic(config.eth_chain_id);
        let mut node = NodeLauncher::new(
            self.secret_key,
            config,
            self.outbound_message_sender.clone(),
        )
        .await?;
        self.shard_nodes.insert(topic.hash(), node.message_sender());
        self.shard_threads
            .spawn(async move { node.start_p2p_node().await });
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        let mut addr: Multiaddr = "/ip4/0.0.0.0".parse().unwrap();

        addr.push(Protocol::Tcp(self.p2p_port));

        self.swarm.listen_on(addr)?;

        if let Some(bootstrap_address) = &self.bootstrap_address {
            self.swarm.dial(
                DialOpts::unknown_peer_id()
                    .address(bootstrap_address.clone())
                    .build(),
            )?;
        }

        // Store our public key in the DHT, indexed by our peer ID.
        self.swarm.behaviour_mut().kademlia.put_record(
            Record::new(
                Multihash::from(self.peer_id), // TODO: Disambiguate this key?
                self.secret_key.node_public_key().as_bytes(),
            ),
            Quorum::One,
        )?;

        let mut terminate = signal::unix::signal(SignalKind::terminate())?;

        loop {
            select! {
                event = self.swarm.next() => match event.expect("swarm stream should be infinite") {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(%address, "started listening");
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer, address) in list {
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer, address);
                            self.swarm.behaviour_mut().kademlia.get_record(Multihash::from(peer).into());
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer, address) in list {
                            self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                            self.swarm.behaviour_mut().kademlia.remove_address(&peer, &address);
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info: identify::Info { listen_addrs, observed_addr, .. }})) => {
                        for address in listen_addrs {
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, address);
                            self.swarm.behaviour_mut().kademlia.get_record(Multihash::from(peer_id).into());
                        }
                        // Mark the address observed for us by the external peer as confirmed.
                        // TODO: We shouldn't trust this, instead we should confirm our own address manually or using
                        // `libp2p-autonat`.
                        self.swarm.add_external_address(observed_addr);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kademlia(KademliaEvent::OutboundQueryProgressed {
                        result: QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord { record: Record { key, value, .. }, .. }))),
                        ..
                    })) => {
                        let peer_id = PeerId::from_multihash(Multihash::from_bytes(key.as_ref())?).expect("key should be a peer ID");
                        let _public_key = NodePublicKey::from_bytes(&value)?;

                        // TODO: temporary, until we have proper dynamic joining!
                        for node in self.shard_nodes.values() {

                            // self.outbound_message_sender.send((Some(peer_id), _topic.to_string().parse()?, Message::AddPeer(self.secret_key.node_public_key())))?;
                            node.send((peer_id, Message::Internal(InternalMessage::AddPeer(_public_key))))?;
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message{
                        message: gossipsub::Message {
                            source,
                            data,
                            topic, ..
                        }, ..
                    })) => {
                        let source = source.expect("message should have a source");
                        let message = serde_json::from_slice::<Message>(&data).unwrap();
                        let message_type = message.name();
                        match message {
                            Message::Internal(_) => {
                                warn!(%source, message_type, "Internal message received over the network!");
                            }
                            Message::External(m) => {
                                debug!(%source, message_type, "message recieved");
                                match self.shard_nodes.get(&topic) {
                                    Some(inbound_message_sender) => inbound_message_sender.send((source, Message::External(m)))?,
                                    None => warn!(?topic, ?source, ?m, "Message received for unknown shard/topic")
                                };
                            }
                        }
                    }

                    SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(request_response::Event::Message { message, peer })) => {
                        match message {
                            request_response::Message::Request {request, channel, ..} => {
                                debug!(%peer, "direct message received");
                                let (shard_id, data) = request;
                                let topic = Self::shard_id_to_topic(shard_id);

                                match self.shard_nodes.get(&topic.hash()) {
                                    Some(inbound_message_sender) => inbound_message_sender.send((peer, Message::External(data)))?,
                                    None => warn!(?topic, ?peer, ?data, "Message received for unknown shard/topic")
                                };

                                let _ = self.swarm.behaviour_mut().request_response.send_response(channel, (shard_id, ExternalMessage::RequestResponse));
                            }
                            request_response::Message::Response {..} => {}
                        }
                    }

                    _ => {},
                },
                message = self.outbound_message_receiver.next() => {
                    let (dest, shard_id, message) = message.expect("message stream should be infinite");
                    let message_type = message.name();
                    let data = serde_json::to_vec(&message).unwrap();

                    let topic = Self::shard_id_to_topic(shard_id);

                    match message {
                        Message::Internal(internal_message) => match internal_message {
                            InternalMessage::LaunchShard(config) => {
                                self.add_shard_node(config).await?;
                            },
                            _ => {
                                warn!(?message_type, "Unexpected internal message in outbound message queue");
                            }
                        }
                        Message::External(external_message) => {
                            match dest {
                                Some(dest) => {
                                    debug!(%dest, message_type, "sending direct message");
                                    let _ = self.swarm.behaviour_mut().request_response.send_request(&dest, (shard_id, external_message));
                                },
                                None => {
                                    debug!(message_type, "sending gossip message");
                                    match self.swarm.behaviour_mut().gossipsub.publish(topic.hash(), data)  {
                                        Ok(_) => {},
                                        Err(e) => {
                                            error!(%e, "failed to publish message");
                                        }
                                    }
                                },
                            }
                        }
                    }
                },
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
