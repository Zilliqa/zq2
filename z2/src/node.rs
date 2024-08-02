use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, Ok, Result};
use serde_json::Value;
use tempfile::NamedTempFile;
use tera::{Context, Tera};
use tokio::{fs::File, io::AsyncWriteExt};

use crate::{
    address::EthereumAddress,
    deployer::{docker_image, Machine, NodeRole},
    validators::Chain,
};

pub struct ChainNode {
    chain_name: String,
    role: NodeRole,
    machine: Machine,
    versions: HashMap<String, String>,
    bootstrap_public_ip: String,
    bootstrap_private_key: String,
    genesis_wallet_private_key: String,
}

impl ChainNode {
    pub fn new(
        chain_name: String,
        role: NodeRole,
        machine: Machine,
        versions: HashMap<String, String>,
        bootstrap_public_ip: String,
        bootstrap_private_key: String,
        genesis_wallet_private_key: String,
    ) -> Self {
        Self {
            chain_name,
            role,
            machine,
            versions,
            bootstrap_public_ip,
            bootstrap_private_key,
            genesis_wallet_private_key,
        }
    }

    pub fn name(&self) -> String {
        self.machine.name.clone()
    }

    pub async fn install(&self) -> Result<()> {
        println!(
            "Installing {} instance {} with address {}",
            self.role, self.machine.name, self.machine.external_address,
        );

        self.import_config_files().await?;
        self.run_provisioning_script().await?;

        Ok(())
    }

    pub async fn upgrade(&self) -> Result<()> {
        println!(
            "Upgrading {} instance {} with address {}",
            self.role, self.machine.name, self.machine.external_address,
        );

        self.import_config_files().await?;
        self.run_provisioning_script().await?;

        // Check the node is making progress
        if self.role == NodeRole::Bootstrap
            || self.role == NodeRole::Validator
            || self.role == NodeRole::Api
        {
            let first_block_number = self.machine.get_local_block_number().await?;
            loop {
                let next_block_number = self.machine.get_local_block_number().await?;
                println!(
                    "Polled block number at {next_block_number}, waiting for {} more blocks",
                    (first_block_number + 10).saturating_sub(next_block_number)
                );
                if next_block_number >= first_block_number + 10 {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn import_config_files(&self) -> Result<()> {
        let temp_config_toml = NamedTempFile::new()?;
        let config_toml = &self
            .create_config_toml(temp_config_toml.path().to_str().unwrap())
            .await?;
        let temp_provisioning_script = NamedTempFile::new()?;
        let provisioning_script = &self
            .create_provisioning_script(temp_provisioning_script.path().to_str().unwrap())
            .await?;

        self.machine
            .copy_to(&[config_toml], "/tmp/config.toml")
            .await?;

        self.machine
            .copy_to(&[provisioning_script], "/tmp/provision_node.py")
            .await?;

        println!("Configuration files imported in the node");

        Ok(())
    }

    async fn run_provisioning_script(&self) -> Result<()> {
        let cmd = "sudo mv /tmp/config.toml /config.toml && sudo python3 /tmp/provision_node.py";
        let output = self.machine.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }

        println!("Provisioning script run successfully");

        Ok(())
    }

    async fn create_config_toml(&self, filename: &str) -> Result<String> {
        let spec_config = Chain::get_toml_contents(&self.chain_name)?;

        let genesis_wallet = EthereumAddress::from_private_key(&self.genesis_wallet_private_key)?;
        let bootstrap_node = EthereumAddress::from_private_key(&self.bootstrap_private_key)?;
        let role_name = self.role.to_string();

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("role", &role_name);
        var_map.insert("external_address", &self.machine.external_address);
        var_map.insert("bootstrap_public_ip", &self.bootstrap_public_ip);
        var_map.insert("bootstrap_peer_id", &bootstrap_node.peer_id);
        var_map.insert("bootstrap_bls_public_key", &bootstrap_node.bls_public_key);
        var_map.insert("genesis_address", &genesis_wallet.address);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(spec_config, &ctx, false)?;
        let config_file = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(config_file.as_bytes()).await?;
        println!("Configuration file created: {filename}");

        Ok(filename.to_owned())
    }

    async fn create_provisioning_script(&self, filename: &str) -> Result<String> {
        // horrific implementation of a rendering engine for the provisioning script used
        // for both first install and upgrade of the ZQ2 network instances.
        // After the proto-testnet launch we can split the provisioning of the infra from the
        // deployment and the configuration of the apps and validator so, we can move it to a proper
        // tera template and remove this.

        let provisioning_script = include_str!("../resources/node_provision.tera.py");
        let role_name = &self.role.to_string();

        let z2_image = &docker_image(
            "zq2",
            self.versions.get("zq2").unwrap_or(&"latest".to_string()),
        )?;

        let otterscan_image = &docker_image(
            "otterscan",
            self.versions
                .get("otterscan")
                .unwrap_or(&"latest".to_string()),
        )?;

        let spout_image = &docker_image(
            "spout",
            self.versions.get("spout").unwrap_or(&"latest".to_string()),
        )?;

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("role", role_name);
        var_map.insert("docker_image", z2_image);
        var_map.insert("otterscan_image", otterscan_image);
        var_map.insert("spout_image", spout_image);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(provisioning_script, &ctx, false)?;
        let provisioning_script = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(provisioning_script.as_bytes()).await?;
        println!("Provisioning file created: {filename}");

        Ok(filename.to_owned())
    }
}

pub async fn get_nodes(
    chain_name: &str,
    project_id: &str,
    node_role: NodeRole,
    versions: HashMap<String, String>,
) -> Result<Vec<ChainNode>> {
    println!("Create the instance list for {node_role}");

    // Create a list of instances we need to update
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
            ],
        )
        .run()
        .await?;

    if !output.success {
        return Err(anyhow!("listing instances failed"));
    }

    let j_output: Value = serde_json::from_slice(&output.stdout)?;

    let instances = j_output
        .as_array()
        .ok_or_else(|| anyhow!("instances is not an array"))?;

    let role_instances = instances
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
                .ok_or_else(|| anyhow!("zone is missing or not a string"))?;
            let external_address = i["networkInterfaces"]
                .get(0)
                .and_then(|ni| ni["accessConfigs"].get(0))
                .and_then(|ac| ac["natIP"].as_str())
                .ok_or_else(|| anyhow!("zone is missing or not a string"))?;
            Ok(Machine {
                project_id: project_id.to_string(),
                zone: zone.to_string(),
                name: name.to_string(),
                labels,
                external_address: external_address.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let bootstrap_instances: Vec<Machine> = role_instances
        .clone()
        .into_iter()
        .filter(|m| {
            m.labels.get("zq2-network") == Some(&chain_name.to_owned())
                && m.labels.get("role") == Some(&"bootstrap".to_string())
        })
        .collect();

    if bootstrap_instances.is_empty() {
        return Err(anyhow!("No bootstrap instances found"));
    }

    let role_instances: Vec<Machine> = role_instances
        .into_iter()
        .filter(|m| {
            m.labels.get("zq2-network") == Some(&chain_name.to_owned())
                && m.labels.get("role") == Some(&node_role.to_string())
        })
        .collect();

    if role_instances.is_empty() {
        println!("No {node_role} instances found");
    }

    let bootstrap_private_keys =
        retrieve_secret_by_role(chain_name, project_id, "bootstrap").await?;
    let bootstrap_private_key = bootstrap_private_keys.first();

    let bootstrap_private_key = if let Some(private_key) = bootstrap_private_key {
        private_key.to_owned()
    } else {
        return Err(anyhow!(
            "Found multiple secrets with role bootstrap in the network {}",
            chain_name
        ));
    };

    let genesis_wallet_private_keys =
        retrieve_secret_by_role(chain_name, project_id, "genesis").await?;
    let genesis_wallet_private_key = genesis_wallet_private_keys.first();

    let genesis_wallet_private_key = if let Some(private_key) = genesis_wallet_private_key {
        private_key.to_owned()
    } else {
        return Err(anyhow!(
            "Found multiple secrets with role genesis in the network {}",
            chain_name
        ));
    };

    Ok(role_instances
        .into_iter()
        .map(|m| {
            ChainNode::new(
                chain_name.to_owned(),
                node_role.clone(),
                m,
                versions.clone(),
                bootstrap_instances[0].external_address.clone(),
                bootstrap_private_key.to_owned(),
                genesis_wallet_private_key.to_owned(),
            )
        })
        .collect::<Vec<_>>())
}

async fn retrieve_secret_by_role(
    chain_name: &str,
    project_id: &str,
    role_name: &str,
) -> Result<Vec<String>> {
    retrieve_secret(
        chain_name,
        project_id,
        format!(
            "labels.zq2-network={} AND labels.role={}",
            chain_name, role_name
        )
        .as_str(),
    )
    .await
}

async fn retrieve_secret(chain_name: &str, project_id: &str, filter: &str) -> Result<Vec<String>> {
    let mut secrets_found = Vec::<String>::new();

    // List secrets with gcloud command
    let output = zqutils::commands::CommandBuilder::new()
        .silent()
        .cmd(
            "gcloud",
            &[
                "secrets",
                "list",
                "--project",
                project_id,
                "--format=json",
                "--filter",
                filter,
            ],
        )
        .run()
        .await?;

    if !output.success {
        return Err(anyhow!("listing secrets failed"));
    }

    // Parse the JSON output
    let secrets: Vec<BTreeMap<String, serde_json::Value>> = serde_json::from_slice(&output.stdout)?;

    // Iterate over the secrets and get their latest versions
    for secret in secrets {
        if let Some(secret_name) = secret.get("name").and_then(|v| v.as_str()) {
            // Find the last '/' in the string
            if let Some(last_slash_pos) = secret_name.rfind('/') {
                let last_part = &secret_name[last_slash_pos + 1..];

                let output = zqutils::commands::CommandBuilder::new()
                    .silent()
                    .cmd(
                        "gcloud",
                        &[
                            "--project",
                            project_id,
                            "secrets",
                            "versions",
                            "access",
                            "latest",
                            "--secret",
                            last_part,
                        ],
                    )
                    .run()
                    .await?;

                if !output.success {
                    return Err(anyhow!("Error executing the command to retrieve secrets with filter '{}' in the network {}", filter, chain_name));
                }

                secrets_found.push(std::str::from_utf8(&output.stdout)?.to_string());
            } else {
                return Err(anyhow!("Error: secret name {} malformed", secret_name));
            }
        }
    }

    Ok(secrets_found)
}
