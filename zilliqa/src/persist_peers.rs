use std::{collections::{hash_map::Entry, HashMap}, mem, task::{Context, Poll}};

use anyhow::{anyhow, Result};
use libp2p::{core::Endpoint, kad::Addresses, swarm::{behaviour::ConnectionEstablished, dummy::ConnectionHandler, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm}, Multiaddr, PeerId};
use sled::Db;
use tracing::{debug, error};

pub struct Behaviour {
    peers: HashMap<PeerId, Addresses>,
    db: Db,
}

impl Behaviour {
    pub fn new(db: Db) -> Result<Self> {
        let mut peers: HashMap<_, Addresses> = HashMap::new();
        
        for kv in db.iter() {
            let (p, a) = kv?;

            tracing::info!("read bytes: k: {}, v: {}", hex::encode(&p), hex::encode(&a));

            let peer_id = PeerId::from_bytes(&p)?;

            let mut i = 0;
            loop {
                if i >= a.len() {
                    break;
                }
                let len_size = mem::size_of::<usize>();
                if (i + len_size) >= a.len() {
                    return Err(anyhow!("malformed address list, expected {len_size} more bytes, but only {} bytes were left", a.len() - i));
                }

                let addr_size = usize::from_be_bytes(a[i..(i + len_size)].try_into().unwrap());
                i += len_size;

                if (i + addr_size) > a.len() {
                    return Err(anyhow!("malformed address list, expected {addr_size} more bytes, but only {} bytes were left", a.len() - i));
                }

                let addr = &a[i..(i + addr_size)];
                let addr = Multiaddr::try_from(addr.to_vec())?;

                tracing::info!(%peer_id, %addr, "got peer from disk");

                match peers.entry(peer_id) {
                    Entry::Occupied(e) => { e.into_mut().insert(addr); },
                    Entry::Vacant(e) => { e.insert(Addresses::new(addr)); },
                }

                i += addr_size;
            }
        }

        tracing::info!(?peers, "read peers from disk");

        Ok(Behaviour {
            peers,
            db,
        })
    }

    pub fn add_address(&mut self, peer_id: PeerId, addr: Multiaddr) {
        tracing::info!(%peer_id, %addr, "added addr");
        match self.peers.entry(peer_id) {
            Entry::Occupied(e) => { e.into_mut().insert(addr); },
            Entry::Vacant(e) => { e.insert(Addresses::new(addr)); },
        }
    }

    fn flush(&self) {
        self.peers.iter().for_each(|(peer_id, addrs)| {
            let addrs = addrs.iter().fold(Vec::new(), |mut acc, addr| {
                acc.extend_from_slice(&addr.len().to_be_bytes());
                acc.extend_from_slice(&addr.to_vec());
                acc
            });

            tracing::info!(%peer_id, "write bytes: {}", hex::encode(&addrs));

            if let Err(e) = self.db.insert(peer_id.to_bytes(), addrs) {
                error!(?e, "failed to flush peers to disk");
            }
        });
    }
}

impl Drop for Behaviour {
    fn drop(&mut self) {
        self.flush();
    }
}


#[derive(Debug)]
pub enum Void {}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = ConnectionHandler;
    type ToSwarm = Void;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        tracing::info!(%peer, %addr, "save peer addr");
        self.add_address(peer, addr.clone());

        Ok(ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        maybe_peer: Option<PeerId>,
        addrs: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        tracing::info!(?maybe_peer, ?addrs, "current addrs on pending connection");
        let Some(peer) = maybe_peer else { return Ok(vec![]); };

        let addrs = self.peers.get(&peer).map(|addrs| addrs.iter().cloned().collect()).unwrap_or_default();

        Ok(addrs)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // TODO
        Poll::Pending
    }
}
