use std::collections::BTreeMap;

use anyhow::{anyhow, Ok, Result};
use serde_json::value::Value;

use super::{
    config::NetworkConfig,
    node::{retrieve_secret_by_role, ChainNode, Machine, NodeRole},
};

#[derive(Clone, Debug)]
pub struct ChainInstance {
    config: NetworkConfig,
    machines: Vec<Machine>,
}

impl ChainInstance {
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            machines: Self::import_machines(&config.name, &config.project_id).await?,
        })
    }

    pub fn name(&self) -> String {
        self.config.name.clone()
    }

    pub fn machines(&self) -> Vec<Machine> {
        self.machines.clone()
    }

    pub fn machines_by_role(&self, role: NodeRole) -> Vec<Machine> {
        let machines: Vec<Machine> = self
            .machines
            .clone()
            .into_iter()
            .filter(|m| m.labels.get("role") == Some(&role.to_string()))
            .collect();

        if machines.is_empty() {
            log::debug!("No machines with role {role} found");
        }

        machines
    }

    async fn import_machines(chain_name: &str, project_id: &str) -> Result<Vec<Machine>> {
        println!("Create the instance list for {chain_name}");

        let output = zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd(
                "gcloud",
                &[
                    "--project",
                    project_id,
                    "compute",
                    "instances",
                    "list",
                    "--format=json",
                    "--filter",
                    &format!("labels.zq2-network={chain_name}"),
                ],
            )
            .run()
            .await?;

        if !output.success {
            return Err(anyhow!("Listing {chain_name} instances failed"));
        }

        let j_output: Value = serde_json::from_slice(&output.stdout)?;

        let instances = j_output
            .as_array()
            .ok_or_else(|| anyhow!("instances is not an array"))?;

        let machines = instances
            .iter()
            .map(|i| {
                let name = i
                    .get("name")
                    .and_then(|n| n.as_str())
                    .ok_or_else(|| anyhow!("name is missing or not a string"))?;
                let zone = i
                    .get("zone")
                    .and_then(|z| z.as_str())
                    .ok_or_else(|| anyhow!("zone is missing or not a string"))?;
                let labels: BTreeMap<String, String> = i
                    .get("labels")
                    .and_then(|z| serde_json::from_value(z.clone()).unwrap_or_default())
                    .ok_or_else(|| anyhow!("labels are missing or not a string"))?;
                let external_address = i["networkInterfaces"]
                    .get(0)
                    .and_then(|ni| ni["accessConfigs"].get(0))
                    .and_then(|ac| ac["natIP"].as_str())
                    .ok_or_else(|| anyhow!("external IP is missing or not a string"))?;
                Ok(Machine {
                    project_id: project_id.to_string(),
                    zone: zone.to_string(),
                    name: name.to_string(),
                    labels,
                    external_address: external_address.to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(machines)
    }

    pub async fn nodes(&self) -> Result<Vec<ChainNode>> {
        let mut nodes = Vec::<ChainNode>::new();

        let mut node_roles = self.config.roles.clone();
        node_roles.sort();

        let eth_chain_id = self.config.eth_chain_id;
        let app_versions = self.config.versions.clone();
        let bootstrap_public_ip = self.bootstrap_public_ip()?;
        let bootstrap_private_key = self.bootstrap_private_key().await?;
        let genesis_wallet_private_key = self.genesis_wallet_private_key().await?;

        for node_role in node_roles {
            let instances = self.machines_by_role(node_role.clone());
            let chain_nodes = instances
                .into_iter()
                .map(|m| {
                    ChainNode::new(
                        self.name(),
                        eth_chain_id,
                        node_role.clone(),
                        m,
                        app_versions.clone(),
                        bootstrap_public_ip.clone(),
                        bootstrap_private_key.clone(),
                        genesis_wallet_private_key.clone(),
                    )
                })
                .collect::<Vec<_>>();
            nodes.extend(chain_nodes);
        }

        Ok(nodes)
    }

    pub fn bootstrap_public_ip(&self) -> Result<String> {
        let instances = self.machines_by_role(NodeRole::Bootstrap);

        if let Some(instance) = instances.first() {
            Ok(instance.external_address.clone())
        } else {
            Err(anyhow!(
                "No bootstrap instances found in the network {}",
                &self.name()
            ))
        }
    }

    pub async fn bootstrap_private_key(&self) -> Result<String> {
        let private_keys =
            retrieve_secret_by_role(&self.config.name, &self.config.project_id, "bootstrap")
                .await?;

        if let Some(private_key) = private_keys.first() {
            Ok(private_key.to_owned())
        } else {
            Err(anyhow!(
                "No secrets with role bootstrap found in the network {}",
                &self.name()
            ))
        }
    }

    pub async fn genesis_wallet_private_key(&self) -> Result<String> {
        let private_keys =
            retrieve_secret_by_role(&self.config.name, &self.config.project_id, "genesis").await?;

        if let Some(private_key) = private_keys.first() {
            Ok(private_key.to_owned())
        } else {
            Err(anyhow!(
                "No secrets with role genesis found in the network {}",
                &self.name()
            ))
        }
    }
}
