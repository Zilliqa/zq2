use eyre::{eyre, Result};
use tokio::{fs, process::Command};

/// Run the eth spout from a sibling directory
pub struct Spout {
    pub config_dir: String,
    pub api_endpoint: String,
    pub explorer_endpoint: String,
}

impl Spout {
    pub fn new(config_dir: &str, api_endpoint: &str, explorer_endpoint: &str) -> Result<Self> {}
}
