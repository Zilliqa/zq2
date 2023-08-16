use crate::collector;
use eyre::{eyre, Result};
use std::io::Write;
use tempfile::NamedTempFile;
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto::SecretKey;

const DATADIR_PREFIX: &str = "z2_node_";

pub struct Setup {
    /// How many nodes should we start?
    pub how_many: usize,
    /// Secret keys for the nodes
    pub secret_keys: Vec<SecretKey>,
    /// The collector, if one is running
    pub collector: Option<collector::Collector>,
    config_files: Vec<NamedTempFile>,
}

impl Setup {
    pub fn new(how_many: usize) -> Result<Self> {
        let mut secret_keys = Vec::new();
        for i in 0..how_many {
            let key = generate_secret_key()?;
            println!("[#{i}] = {}", key.to_hex());
            secret_keys.push(key);
        }

        let first_key = secret_keys[0].node_public_key().to_string();
        let first_peer_id = secret_keys[0]
            .to_libp2p_keypair()
            .public()
            .to_peer_id()
            .to_string();

        let mut config_files = Vec::new();
        for i in 0..how_many {
            let mut config_file = NamedTempFile::new()?;
            write!(
                config_file,
                r#"
                    data_dir = "{DATADIR_PREFIX}{i}"
                    genesis_committee = [ [ "{first_key}", "{first_peer_id}" ] ]
                "#
            )?;

            println!("config file is : {:?}", config_file);

            config_files.push(config_file);
        }

        Ok(Self {
            how_many,
            secret_keys,
            collector: None,
            config_files,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Generate a collector
        self.collector =
            Some(collector::Collector::new(&self.secret_keys, &self.config_files).await?);
        if let Some(mut c) = self.collector.take() {
            c.complete().await?;
        }
        Ok(())
    }
}

pub fn generate_secret_key() -> Result<SecretKey> {
    SecretKey::new().map_err(|err| eyre!(Box::new(err)))
}
