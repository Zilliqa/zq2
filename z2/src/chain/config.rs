use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::node::NodeRole;
use crate::github;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub(super) name: String,
    pub(super) eth_chain_id: u64,
    pub(super) project_id: String,
    pub(super) roles: Vec<NodeRole>,
    pub(super) versions: HashMap<String, String>,
}

impl NetworkConfig {
    pub async fn new(
        name: String,
        eth_chain_id: u64,
        project_id: String,
        roles: Vec<NodeRole>,
    ) -> Result<Self> {
        let mut versions = HashMap::new();

        for r in roles.clone() {
            if r.to_string().to_lowercase() == "validator" {
                versions.insert(
                    "zq2".to_string(),
                    github::get_release_or_commit("zq2").await?,
                );
            } else if r.to_string().to_lowercase() == "apps" {
                versions.insert(
                    "spout".to_string(),
                    github::get_release_or_commit("zilliqa-developer").await?,
                );
                versions.insert("otterscan".to_string(), "latest".to_string());
            }
        }

        Ok(Self {
            name,
            eth_chain_id,
            project_id,
            roles,
            versions,
        })
    }

    pub async fn from_file(file: &str) -> Result<Self> {
        let config = tokio::fs::read_to_string(file).await?;
        let config: Self = serde_yaml::from_str(&config)?;
        Ok(config)
    }
}
