use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::node::NodeRole;
use crate::github;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub(super) name: String,
    pub(super) eth_chain_id: u64,
    pub(super) roles: Vec<NodeRole>,
    pub(super) versions: HashMap<String, String>,
}

impl NetworkConfig {
    pub async fn new(name: String, eth_chain_id: u64, roles: Vec<NodeRole>) -> Result<Self> {
        let mut versions = HashMap::new();

        for r in roles.clone() {
            if r.to_string().to_lowercase() == "validator" {
                versions.insert(
                    "zq2".to_string(),
                    github::get_release_or_commit("zq2").await?,
                );
            } else if r.to_string().to_lowercase() == "apps" {
                versions.insert(
                    "otterscan".to_string(), 
                    "latest".to_string()
                );
                versions.insert(
                    "spout".to_string(),
                    github::get_release_or_commit("zilliqa-developer").await?,
                );
                versions.insert(
                    "stats_dashboard".to_string(),
                    github::get_release_or_commit("ethstats-server").await?,
                );
                versions.insert(
                    "stats_agent".to_string(),
                    github::get_release_or_commit("eth-net-intelligence-api").await?,
                );
                versions.insert(
                    "zq2_metrics".to_string(),
                    github::get_release_or_commit("zq2-metrics").await?,
                );
            }
        }

        Ok(Self {
            name,
            eth_chain_id,
            roles,
            versions,
        })
    }

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
