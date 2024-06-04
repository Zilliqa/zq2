#![allow(unused_imports)]

use std::{
    collections::HashMap,
    fmt::{self, Display},
    path::PathBuf,
    process::{self, Stdio},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use bitvec::order::verify_for_type;
use clap::ValueEnum;
use git2::Repository;
use regex::Regex;
use revm::handler::validation;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use tempfile::TempDir;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use zilliqa::node::Node;

use crate::github::{self, get_release_or_commit};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Components {
    #[serde(rename = "zq2")]
    ZQ2,
    #[serde(rename = "otterscan")]
    Otterscan,
    #[serde(rename = "spout")]
    Spout,
}

impl FromStr for Components {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "zq2" => Ok(Components::ZQ2),
            "otterscan" => Ok(Components::Otterscan),
            "spout" => Ok(Components::Spout),
            _ => Err(anyhow!("Component not supported")),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct NetworkConfig {
    name: String,
    project_id: String,
    regions: Vec<String>,
    roles: Vec<NodeRole>,
    versions: HashMap<String, String>,
}

pub fn docker_image(component: &str, version: &str) -> Result<String> {
    // Define regular expressions for semantic version and 8-character commit ID
    let semver_re = Regex::new(r"^v\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$").unwrap();
    let commit_id_re = Regex::new(r"^[a-f0-9]{8}$").unwrap();
    match component.to_string().parse::<Components>()? {
        Components::ZQ2 => {
            if semver_re.is_match(version) {
                Ok(format!(
                    "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zq2:{}",
                    version
                ))
            } else if commit_id_re.is_match(version) {
                Ok(format!(
                    "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-private/zq2:{}",
                    version
                ))
            } else {
                Err(anyhow!("Invalid version for ZQ2"))
            }
        }
        Components::Spout => Ok(format!(
            "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/eth-spout:{}",
            version
        )),
        Components::Otterscan => Ok(format!("docker.io/zilliqa/otterscan:{}", version)),
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, ValueEnum)]
pub enum NodeRole {
    #[serde(rename = "validator")]
    /// Virtual machine validator
    Validator,
    #[serde(rename = "apps")]
    /// Virtual machine apps
    Apps,
}

impl FromStr for NodeRole {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "validator" => Ok(NodeRole::Validator),
            "apps" => Ok(NodeRole::Apps),
            _ => Err(anyhow!("Node role not supported")),
        }
    }
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NodeRole::Apps => write!(f, "apps"),
            NodeRole::Validator => write!(f, "validator"),
        }
    }
}

impl NetworkConfig {
    async fn new(name: String, project_id: String, roles: Vec<NodeRole>) -> Result<Self> {
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
            project_id,
            roles,
            versions,
            regions: vec!["asia-southeast1".to_owned()],
        })
    }
}

pub struct Machine {
    pub project_id: String,
    pub zone: String,
    pub name: String,
}

impl Machine {
    pub async fn copy_to(&self, file_from: &str, file_to: &str) -> Result<()> {
        let tgt_spec = format!("{0}:{file_to}", &self.name);
        zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd(
                "gcloud",
                &[
                    "compute",
                    "scp",
                    "--project",
                    &self.project_id,
                    "--zone",
                    &self.zone,
                    "--tunnel-through-iap",
                    "--scp-flag=-r",
                    file_from,
                    &tgt_spec,
                ],
            )
            .run()
            .await?;
        Ok(())
    }

    pub async fn run(&self, cmd: &str) -> Result<zqutils::commands::CommandOutput> {
        let output: zqutils::commands::CommandOutput = zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd(
                "gcloud",
                &[
                    "compute",
                    "ssh",
                    "--project",
                    &self.project_id,
                    "--zone",
                    &self.zone,
                    &self.name,
                    "--tunnel-through-iap",
                    "--ssh-flag=",
                    "--command",
                    cmd,
                ],
            )
            .run_for_output()
            .await?;
        Ok(output)
    }
}
async fn get_local_block_number(instance: &Machine) -> Result<u64> {
    let inner_command = r#"curl -s http://localhost:4201 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}'"#;
    let output = instance.run(inner_command).await?;
    if !output.success {
        return Err(anyhow!(
            "getting local block number failed: {:?}",
            output.stderr
        ));
    }

    let response: Value = serde_json::from_slice(&output.stdout)?;
    let block_number = response
        .get("result")
        .ok_or_else(|| anyhow!("response has no result"))?
        .as_str()
        .ok_or_else(|| anyhow!("result is not a string"))?
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("result does not start with 0x"))?;
    let block_number = u64::from_str_radix(block_number, 16)?;

    Ok(block_number)
}

pub async fn new(network_name: &str, project_id: &str, roles: Vec<NodeRole>) -> Result<()> {
    let config =
        NetworkConfig::new(network_name.to_string(), project_id.to_string(), roles).await?;
    let content = serde_yaml::to_string(&config)?;
    fs::write(format!("{network_name}.yaml"), content).await?;
    Ok(())
}

pub async fn create_provisioning_script(
    provisioning_script: &str,
    file_name: &str,
    role: &str,
    config: &NetworkConfig,
) -> Result<()> {
    let mut result: Vec<String> = Vec::new();
    // horrific implementation of a rendering engine for the provisioning script used
    // for both first install and upgrade of the ZQ2 network instances.
    // After the proto-testnet launch we can split the provisioning of the infra from the
    // deployment and the configuration of the apps and validator so, we can move it to a proper
    // tera template and remove this.
    for line in provisioning_script.split('\n') {
        if line.contains("$${") {
            result.push(line.replace("$${", "${"));
        } else if line.starts_with("ZQ2_IMAGE") {
            println!("Found ZQ2 image");
            result.push(format!(
                "ZQ2_IMAGE='{}'",
                docker_image(
                    "zq2",
                    config.versions.get("zq2").unwrap_or(&"latest".to_string())
                )?
            ));
        } else if line.starts_with("OTTERSCAN_IMAGE") {
            println!("Found Otterscan image");
            result.push(format!(
                "OTTERSCAN_IMAGE='{}'",
                docker_image(
                    "otterscan",
                    config
                        .versions
                        .get("otterscan")
                        .unwrap_or(&"latest".to_string())
                )?
            ));
        } else if line.starts_with("SPOUT_IMAGE") {
            println!("Found Spout image");
            result.push(format!(
                "SPOUT_IMAGE='{}'",
                docker_image(
                    "spout",
                    config
                        .versions
                        .get("spout")
                        .unwrap_or(&"latest".to_string())
                )?
            ));
        } else if line.contains("${genesis_key}") {
            result.push(line.replace(
                "${genesis_key}",
                "\"\" + base64.b64decode(query_metadata_key(GENESIS_KEY)).decode('utf-8') + \"\"",
            ));
        } else if line.contains("go(role=\"${role}\")") {
            result.push(line.replace("go(role=\"${role}\")", &format!("go(role=\"{}\")", role)));
        } else {
            result.push(line.to_string())
        }
    }
    let resulting_code = result.join("\n");
    let mut fh = File::create(file_name).await?;
    fh.write_all(resulting_code.as_bytes()).await?;
    println!("Provisioning file created: {file_name}");
    Ok(())
}

pub async fn upgrade(config_file: &str) -> Result<()> {
    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;

    let mut validators: Vec<Machine> = Vec::new();
    let mut apps: Vec<Machine> = Vec::new();
    for r in config.roles.clone() {
        let r_name = r.to_string();
        let file_name = &format!("provision_{}.py", r_name);
        create_provisioning_script(
            include_str!("../../infra/tf/modules/node/scripts/node_provision.py.tpl"),
            file_name,
            &r.to_string(),
            &config,
        )
        .await?;

        println!("Create the instance list for {r_name}");

        // Create a list of instances we need to update
        let output = zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd(
                "gcloud",
                &[
                    "--project",
                    &config.project_id,
                    "compute",
                    "instances",
                    "list",
                    "--format=json",
                    &format!("--filter=labels.zq2-network={}", config.name),
                    &format!("--filter=labels.role={}", r_name),
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
                let project_id = &config.project_id;
                Ok(Machine {
                    project_id: project_id.to_string(),
                    zone: zone.to_string(),
                    name: name.to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        if r_name == "validator" {
            validators = role_instances
        } else if r_name == "apps" {
            apps = role_instances;
            if apps.is_empty() {
                println!("No apps instances found");
            }
        }
    }

    for validator in validators {
        println!("Upgrading instance {}", validator.name);
        validator
            .copy_to("./provision_validator.py", "/tmp/provision_validator.py")
            .await?;
        let cmd = "sudo python3 /tmp/provision_validator.py";
        let output = validator.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }
        // Check the node is making progress
        let first_block_number = get_local_block_number(&validator).await?;
        loop {
            let next_block_number = get_local_block_number(&validator).await?;
            println!(
                "Polled block number at {next_block_number}, waiting for {} more blocks",
                (first_block_number + 10).saturating_sub(next_block_number)
            );
            if next_block_number >= first_block_number + 10 {
                break;
            }
        }
    }

    for app in apps {
        println!("Upgrading instance {}", app.name);
        app.copy_to("./provision_apps.py", "/tmp/provision_apps.py")
            .await?;
        let cmd = "sudo python3 /tmp/provision_apps.py";
        let output = app.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }
    }

    Ok(())
}
