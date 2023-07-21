use std::io::ErrorKind::AlreadyExists;
use std::path::Path;
use std::{fs::File, io::Write};

use crate::collector;
use eyre::{eyre, Result};
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto;

/// Filename prefix for per-node config files
const CFG_PREFIX: &str = "z2_node_"; //.toml
const DATADIR_PREFIX: &str = "z2_node_";

pub struct Setup {
    /// How many nodes should we start?
    pub how_many: usize,
    /// Secret keys for the nodes (we deliberately elect not to know too much about them)
    pub secret_keys: Vec<String>,
    /// The collector, if one is running
    pub collector: Option<collector::Collector>,
}

impl Setup {
    pub fn new(how_many: usize) -> Result<Self> {
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

    pub fn config_path(index: usize) -> String {
        format!("{CFG_PREFIX}{index}.toml")
    }

    pub fn ensure_config_files_exist(&self) -> Result<()> {
        for i in 0..self.how_many {
            let path = Self::config_path(i);
            let path = Path::new(&path);
            match File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(mut file) => {
                    println!("Creating config file {}", path.to_string_lossy());
                    writeln!(file, "data_dir = \"{DATADIR_PREFIX}{i}\"")?;
                }
                Err(already_exists) if already_exists.kind() == AlreadyExists => {
                    // ignore existing files
                }
                Err(e) => return Err(eyre!("Failed to open config file: {e}")),
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        // Generate a collector
        self.ensure_config_files_exist()?;
        self.collector = Some(collector::Collector::new(&self.secret_keys).await?);
        if let Some(mut c) = self.collector.take() {
            c.complete().await?;
        }
        Ok(())
    }
}

pub fn generate_secret_key_hex() -> Result<String> {
    crypto::SecretKey::new()
        .map_err(|err| eyre!(Box::new(err)))?
        .to_hex()
        .map_err(|err| eyre!(Box::new(err)))
}
