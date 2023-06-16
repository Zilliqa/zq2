use crate::collector;
use eyre::{eyre, Result};
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto;

pub struct Setup {
    /// How many nodes should we start?
    pub how_many: u32,
    /// Secret keys for the nodes (we deliberately elect not to know too much about them)
    pub secret_keys: Vec<String>,
    /// The collector, if one is running
    pub collector: Option<collector::Collector>,
}

impl Setup {
    pub fn new(how_many: u32) -> Result<Self> {
        // Generate some keys
        let mut secret_keys: Vec<String> = Vec::new();
        for i in 0..how_many {
            let key = generate_secret_key_hex()?;
            println!("[#{i}] = {key}");
            secret_keys.push(key);
        }
        Ok(Self {
            how_many,
            secret_keys,
            collector: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Generate a collector
        self.collector = Some(collector::Collector::new(&self.secret_keys).await?);
        if let Some(mut c) = self.collector.take() {
            c.complete().await?;
        }
        Ok(())
    }
}

pub fn generate_secret_key_hex() -> Result<String> {
    Ok(crypto::SecretKey::new()
        .map_err(|err| eyre!(Box::new(err)))?
        .to_hex())
}
