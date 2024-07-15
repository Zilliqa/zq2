use crate::crypto::SecretKey;
use anyhow::Result;
use std::{fs, path::PathBuf};

pub mod cfg;

pub trait Args {
    fn secret_key(&self) -> &SecretKey;
    fn config_file(&self) -> &PathBuf;
}
pub fn read_config<T: Args>(args: &T) -> Result<cfg::Config> {
    let config_file = &args.config_file();
    let config_content = if config_file.exists() {
        fs::read_to_string(&config_file)?
    } else {
        panic!("Please specify a config file");
    };

    Ok(toml::from_str(&config_content)?)
}
