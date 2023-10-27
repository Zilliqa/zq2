use std::io::Write;

use eyre::{eyre, Result};
use tempfile::NamedTempFile;
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto::SecretKey;

use crate::collector;

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
                    [[nodes]]
                    {}data_dir = "{DATADIR_PREFIX}{i}"
                    eth_chain_id = 0x8001
                    consensus.genesis_committee = [ [ "{first_key}", "{first_peer_id}" ] ]
                    consensus.genesis_accounts = [
                        ["7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "5000000000000000000000"],
                        ["2B5AD5c4795c026514f8317c7a215E218DcCD6cF", "5000000000000000000000"],
                        ["6813Eb9362372EEF6200f3b1dbC3f819671cBA69", "5000000000000000000000"],
                        ["1efF47bc3a10a45D4B230B5d10E37751FE6AA718", "5000000000000000000000"],
                        ]
                "#,
                if i == 0 { "" } else { "disable_rpc = true\n" }
            )?;
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
