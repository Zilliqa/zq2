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

    pub fn get_version(&self, key: &str) -> String {
        let default_value = &String::from("latest");
        let version = self.config.versions.get(key).unwrap_or(default_value);
        version.to_owned()
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
            .filter(|i| {
                i.get("status")
                    .and_then(|status| status.as_str())
                    .map(|status_str| status_str == "RUNNING")
                    .unwrap_or(false) // Exclude instances without a valid status or those not in RUNNING state
            })
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

        for node_role in node_roles {
            let chain_nodes = self.nodes_by_role(node_role).await?;
            nodes.extend(chain_nodes);
        }

        Ok(nodes)
    }

    pub async fn nodes_by_role(&self, role: NodeRole) -> Result<Vec<ChainNode>> {
        let mut nodes = Vec::<ChainNode>::new();

        let eth_chain_id = self.config.eth_chain_id;

        let instances = self.machines_by_role(role.clone());
        let chain_nodes = instances
            .into_iter()
            .map(|m| ChainNode::new(self.clone(), eth_chain_id, role.clone(), m))
            .collect::<Vec<_>>();
        nodes.extend(chain_nodes);

        Ok(nodes)
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
