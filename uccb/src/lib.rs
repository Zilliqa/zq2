use std::{fs, path::PathBuf};

use anyhow::Result;

pub mod cfg;
pub mod client;

pub fn read_config(config_file: &PathBuf) -> Result<cfg::Config> {
    let config_content = if config_file.exists() {
        fs::read_to_string(config_file)?
    } else {
        panic!("Please specify a config file");
    };

    Ok(toml::from_str(&config_content)?)
}
