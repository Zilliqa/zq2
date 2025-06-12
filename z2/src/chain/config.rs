use std::collections::HashMap;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use super::node::NodeRole;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub(super) name: String,
    pub(super) eth_chain_id: u64,
    pub(super) roles: Vec<NodeRole>,
    pub(super) versions: HashMap<String, String>,
}

impl NetworkConfig {
    pub async fn from_file(file: &str) -> Result<Self> {
        let config = tokio::fs::read_to_string(file)
            .await
            .context(format!("Cannot read {file}"))?;
        let config: Self = serde_yaml::from_str(&config).context(format!(
            "{file} does not contain a valid YAML network config object"
        ))?;
        Ok(config)
    }
}
