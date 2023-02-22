mod crypto;
mod message;
mod node;

use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
use crypto::{PublicKey, SecretKey};
use libp2p::{
    core::upgrade,
    futures::StreamExt,
    gossipsub::{
        Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, IdentTopic,
        MessageAuthenticity,
    },
    identify,
    kad::{
        store::MemoryStore, GetRecordOk, Kademlia, KademliaEvent, PeerRecord, QueryResult, Quorum,
        Record,
    },
    mdns, mplex,
    multihash::Multihash,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, PeerId, Swarm, Transport,
};
use node::Node;
use tokio::{
    select,
    sync::mpsc,
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::message::Message;

#[derive(Debug, Parser)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: Gossipsub,
    mdns: mdns::tokio::Behaviour,
    kademlia: Kademlia<MemoryStore>,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let key_pair = args.secret_key.to_libp2p_keypair();
    let peer_id = PeerId::from(key_pair.public());
    println!("Peer ID: {peer_id:?}");

    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseAuthenticated::xx(&key_pair)?)
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let behaviour = Behaviour {
        gossipsub: Gossipsub::new(
            MessageAuthenticity::Signed(key_pair.clone()),
            GossipsubConfigBuilder::default()
                .build()
                .map_err(|e| anyhow!(e))?,
        )
        .map_err(|e| anyhow!(e))?,
        mdns: mdns::Behaviour::new(Default::default())?,
        kademlia: Kademlia::new(peer_id, MemoryStore::new(peer_id)),
        identify: identify::Behaviour::new(identify::Config::new(
            "/ipfs/id/1.0.0".to_owned(),
            key_pair.public(),
        )),
    };

    let mut swarm = Swarm::with_tokio_executor(transport, behaviour, peer_id);

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let topic = IdentTopic::new("topic");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Store our public key in the DHT, indexed by our peer ID.
    swarm.behaviour_mut().kademlia.put_record(
        Record::new(
            Multihash::from(peer_id), // TODO: Disambiguate this key?
            args.secret_key.public_key().as_bytes(),
        ),
        Quorum::One,
    )?;

    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let mut message_receiver = UnboundedReceiverStream::new(message_receiver);
    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    let mut reset_timeout_receiver = UnboundedReceiverStream::new(reset_timeout_receiver);

    let mut node = Node::new(
        peer_id,
        args.secret_key,
        message_sender,
        reset_timeout_sender,
    )?;

    let sleep = time::sleep(Duration::from_secs(5));
    tokio::pin!(sleep);
    loop {
        select! {
            event = swarm.next() => match event.expect("swarm stream should be infinite") {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {address:?}");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer, address) in list {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                        swarm.behaviour_mut().kademlia.add_address(&peer, address);
                        swarm.behaviour_mut().kademlia.get_record(Multihash::from(peer).into());
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, address) in list {
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                        swarm.behaviour_mut().kademlia.remove_address(&peer, &address);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info: identify::Info { listen_addrs, .. }})) => {
                    for address in listen_addrs {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, address);
                        swarm.behaviour_mut().kademlia.get_record(Multihash::from(peer_id).into());
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kademlia(KademliaEvent::OutboundQueryProgressed {
                    result: QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord { record: Record { key, value, .. }, .. }))),
                    ..
                })) => {
                    let peer_id = PeerId::from_multihash(Multihash::from_bytes(key.as_ref())?).expect("key should be a peer ID");
                    let public_key = PublicKey::from_bytes(&value)?;

                    node.add_peer(peer_id, public_key)?;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(GossipsubEvent::Message{
                    message: GossipsubMessage {
                        source,
                        data, ..
                    }, ..
                })) => {
                    let source = source.expect("message should have a source");
                    let message = serde_json::from_slice::<Message>(&data).unwrap();
                    println!("Received {} from {source:?}", message.name());
                    node.handle_message(source, message).unwrap();
                }
                _ => {}
            },
            message = message_receiver.next() => {
                let (peer_id, message) = message.expect("message stream should be infinite");
                println!("Sending {} to {peer_id:?}", message.name());
                let data = serde_json::to_vec(&message).unwrap();
                swarm.behaviour_mut().gossipsub.publish(topic.hash(), data).ok();
            },
            () = &mut sleep => {
                println!("Timeout elapsed");
                node.handle_timeout().unwrap();
                sleep.as_mut().reset(Instant::now() + Duration::from_secs(5));
            },
            r = reset_timeout_receiver.next() => {
                let () = r.expect("reset timeout stream should be infinite");
                println!("Timeout reset");
                sleep.as_mut().reset(Instant::now() + Duration::from_secs(5));
            },
        }
    }
}
