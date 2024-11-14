// Exists to keep all my debug crud in one place so it can be easily removed later.

use anyhow::Result;
use libp2p::PeerId;

#[derive(Debug)]
pub struct Director {
    // Only talk to these nodes.
    whitelist: Option<Vec<PeerId>>,
}

impl Director {
    pub fn new() -> Result<Director> {
        Ok(Self { whitelist: None })
    }

    pub fn whitelist(&mut self, whitelist: Option<Vec<PeerId>>) -> Result<()> {
        self.whitelist = whitelist;
        Ok(())
    }
}
