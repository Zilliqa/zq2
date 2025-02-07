use std::{collections::BTreeMap, str::FromStr};

use anyhow::{anyhow, Ok, Result};
use serde_json::value::Value;

use super::{
    config::NetworkConfig,
    node::{retrieve_secret_by_role, ChainNode, Machine, NodeRole},
    Chain,
};

#[derive(Clone, Debug)]
pub struct ChainInstance {
    config: NetworkConfig,
    machines: Vec<Machine>,
    persistence_url: Option<String>,
    checkpoint_url: Option<String>,
}

impl ChainInstance {
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        let chain = Chain::from_str(&config.name.clone())?;
        Ok(Self {
            config: config.clone(),
            machines: Self::import_machines(&config.name, chain.get_project_id()?).await?,
            persistence_url: None,
            checkpoint_url: None,
        })
    }

    pub fn name(&self) -> String {
        self.config.name.clone()
    }

    pub fn chain(&self) -> Result<Chain> {
        Ok(Chain::from_str(&self.name())?)
    }

    pub fn persistence_url(&self) -> Option<String> {
        self.persistence_url.clone()
    }

    pub fn set_persistence_url(&mut self, persistence_url: Option<String>) {
        self.persistence_url = persistence_url;
    }

    pub fn checkpoint_url(&self) -> Option<String> {
        self.checkpoint_url.clone()
    }

    pub fn set_checkpoint_url(&mut self, checkpoint_url: Option<String>) {
        self.checkpoint_url = checkpoint_url;
    }

    pub fn machines(&self) -> Vec<Machine> {
        let mut machines = self.machines.clone();
        machines.sort_by_key(|machine| machine.name.to_owned());
        machines
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
                // Zone is often reported as a URL. get only the last element..
                let zone = i
                    .get("zone")
                    .and_then(|z| z.as_str())
                    .map(|z| z.rsplit_once('/').map_or(z, |(_, y)| y))
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

        nodes.sort_by_key(|node| node.name());

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

    pub async fn genesis_private_key(&self) -> Result<String> {
        let private_keys = retrieve_secret_by_role(
            &self.config.name,
            self.chain()?.get_project_id()?,
            "genesis",
        )
        .await?;

        if let Some(private_key) = private_keys.first() {
            Ok(private_key.value().await?)
        } else {
            Err(anyhow!(
                "No secrets with role genesis found in the network {}",
                &self.name()
            ))
        }
    }

    pub async fn stats_dashboard_key(&self) -> Result<String> {
        let private_keys = retrieve_secret_by_role(
            &self.config.name,
            self.chain()?.get_project_id()?,
            "stats-dashboard",
        )
        .await?;

        if let Some(private_key) = private_keys.first() {
            Ok(private_key.value().await?)
        } else {
            Err(anyhow!(
                "No secrets with role stats-dashboard found in the network {}",
                &self.name()
            ))
        }
    }

    pub async fn run_rpc_call(
        &self,
        method: &str,
        params: &Option<String>,
        timeout: usize,
    ) -> Result<String> {
        let endpoint = self.chain()?.get_api_endpoint()?;
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"{}\",\"params\":{}}}",
            method,
            params.clone().unwrap_or("[]".to_string()),
        );

        let args = &[
            "--max-time",
            &timeout.to_string(),
            "-X",
            "POST",
            "-H",
            "Content-Type:application/json",
            "-H",
            "accept:application/json,*/*;q=0.5",
            "--data",
            &body,
            &endpoint,
        ];

        let output = zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd("curl", args)
            .run_for_output()
            .await?;
        if !output.success {
            return Err(anyhow!(
                "getting local block number failed: {:?}",
                output.stderr
            ));
        }

        Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
    }
}
