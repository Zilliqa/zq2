use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, Ok, Result};
use serde_json::Value;
use tera::{Context, Tera};
use tokio::{fs::File, io::AsyncWriteExt};

use crate::{
    deployer::{docker_image, Machine, NodeRole},
    validators,
};

pub struct ChainNode {
    chain_name: String,
    role: NodeRole,
    pub machine: Machine,
    versions: HashMap<String, String>,
}

impl ChainNode {
    pub fn new(
        chain_name: String,
        role: NodeRole,
        machine: Machine,
        versions: HashMap<String, String>,
    ) -> Self {
        Self {
            chain_name,
            role,
            machine,
            versions,
        }
    }

    pub async fn import_config_files(&self) -> Result<()> {
        let provisioning_script = &self.create_provisioning_script().await?;
        self.write("config.toml").await?;

        self.machine
            .copy_to(&[provisioning_script, "config.toml"], "/tmp/")
            .await?;

        println!("Configuration files imported in the node");

        Ok(())
    }

    pub async fn run_provisioning_script(&self) -> Result<()> {
        let cmd = "sudo mv /tmp/config.toml /config.toml && sudo python3 /tmp/provision_node.py";
        let output = self.machine.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }

        println!("Provisioning script run successfully");

        Ok(())
    }

    async fn write(&self, filename: &str) -> Result<()> {
        let mut spec_config = validators::get_chain_spec_config(&self.chain_name).await?;

        if self.role == NodeRole::Bootstrap {
            spec_config
                .as_table_mut()
                .unwrap()
                .remove("bootstrap_address");
        }

        let external_address = format!("/ip4/{}/tcp/3333", self.machine.external_address.clone());

        spec_config.as_table_mut().unwrap().insert(
            "external_address".to_owned(),
            toml::Value::String(external_address),
        );

        let mut file = File::create(filename).await?;
        file.write_all(toml::to_string(&spec_config)?.as_bytes())
            .await?;
        println!("Configuration file created: {filename}");
        Ok(())
    }

    async fn create_provisioning_script(&self) -> Result<String> {
        // horrific implementation of a rendering engine for the provisioning script used
        // for both first install and upgrade of the ZQ2 network instances.
        // After the proto-testnet launch we can split the provisioning of the infra from the
        // deployment and the configuration of the apps and validator so, we can move it to a proper
        // tera template and remove this.

        let provisioning_script = include_str!("../resources/node_provision.tera.py");
        let role_name = &self.role.to_string();
        let filename = "provision_node.py";

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

    Ok(role_instances
        .into_iter()
        .map(|m| {
            ChainNode::new(
                chain_name.to_owned(),
                node_role.clone(),
                m,
                versions.clone(),
            )
        })
        .collect::<Vec<_>>())
}
