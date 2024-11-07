// Exists to keep all my debug crud in one place so it can be easily removed later.

use anyhow::Result;
use libp2p::PeerId;
use std::collections::HashSet;
use tracing::*;

#[derive(Debug)]
pub struct Director {
    // Only talk to these nodes.
    whitelist: Option<HashSet<PeerId>>,
}

impl Director {
    pub fn new() -> Result<Director> {
        Ok(Self { whitelist: None })
    }

    pub fn whitelist(&mut self, whitelist: Option<Vec<PeerId>>) -> Result<()> {
        trace!("director: Whitelist set to {whitelist:?}");
        self.whitelist = whitelist.map(|x| x.iter().cloned().collect::<HashSet<PeerId>>());
        Ok(())
    }

    pub fn is_allowed(&self, id: &str, from: &PeerId) -> Result<bool> {
        let result = match &self.whitelist {
            None => true,
            Some(peers) => peers.contains(from),
        };
        trace!("director: message {id} from {from:?} is_allowed {result}");
        Ok(result)
    }
}
