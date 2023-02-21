mod crypto;
mod message;
mod node;

use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
use crypto::{PublicKey, SecretKey};
use itertools::Itertools;
use libp2p::{
    core::upgrade,
    futures::StreamExt,
    gossipsub::{
        Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, IdentTopic,
        MessageAuthenticity,
    },
    mdns, mplex, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, PeerId, Swarm, Transport,
};
use message::Block;
use node::{Node, ValidatorSet};
use tokio::{
    select,
    sync::mpsc,
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::message::Message;

#[derive(Debug, Parser)]
struct Args {
    index: u16,
    #[arg(value_parser = validator_set_from_str)]
    committee: ValidatorSet,
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
}

fn validator_set_from_str(s: &str) -> Result<ValidatorSet> {
    let validators = s.split(',').map(|v| {
        let Some((key, rest)) = v.split_once(':') else { return Err(anyhow!("invalid validator: {v}")); };
        let Some((libp2p_key, weight)) = rest.split_once(':') else { return Err(anyhow!("invalid validator: {v}")); };

        let key = PublicKey::from_hex(key)?;
        let peer_id: PeerId = libp2p::identity::PublicKey::from_protobuf_encoding(&hex::decode(libp2p_key)?)?.into();
        let weight: u128 = weight.parse()?;

        Ok((key, peer_id, weight))
    });

    let (public_keys, peer_ids, weights): (Vec<_>, Vec<_>, Vec<_>) =
        itertools::process_results(validators, |iter| iter.multiunzip())?;

    Ok(ValidatorSet {
        public_keys,
        peer_ids,
        weights,
    })
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: Gossipsub,
    mdns: mdns::tokio::Behaviour,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Public key: {}", args.secret_key.public_key());

    let genesis = Block::genesis(args.committee.peer_ids.len());

    let key_pair = args.secret_key.to_libp2p_keypair()?;
    println!(
        "libp2p public key: {:?}",
        hex::encode(key_pair.public().to_protobuf_encoding())
    );
    let peer_id = PeerId::from(key_pair.public());
    println!("Peer ID: {peer_id:?}");

    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseAuthenticated::xx(&key_pair)?)
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let behaviour = Behaviour {
        gossipsub: Gossipsub::new(
            MessageAuthenticity::Signed(key_pair),
            GossipsubConfigBuilder::default()
                .build()
                .map_err(|e| anyhow!(e))?,
        )
        .map_err(|e| anyhow!(e))?,
        mdns: mdns::Behaviour::new(Default::default())?,
    };

    let mut swarm = Swarm::with_tokio_executor(transport, behaviour, peer_id);

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let topic = IdentTopic::new("topic");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let mut message_receiver = UnboundedReceiverStream::new(message_receiver);
    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    let mut reset_timeout_receiver = UnboundedReceiverStream::new(reset_timeout_receiver);

    let mut node = Node::new(
        args.index,
        args.committee,
        args.secret_key,
        genesis,
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
                    for (peer, _) in list {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, _) in list {
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                    }
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
