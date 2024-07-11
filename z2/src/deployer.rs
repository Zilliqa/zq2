#![allow(unused_imports)]

use std::{
    collections::{BTreeMap, HashMap},
    fmt::{self, Display},
    io::Write,
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
use tempfile::{NamedTempFile, TempDir};
use tera::{Context, Tera};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use zilliqa::node::Node;

use crate::{github::{self, get_release_or_commit}, validators};

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
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Virtual machine validator
    Validator,
    /// Virtual machine apps
    Apps,
    /// Virtual machine bootstrap
    Bootstrap,
    /// Virtual machine sentry
    Sentry,
    /// Virtual machine checkpoint
    Checkpoint,
}

impl FromStr for NodeRole {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "validator" => Ok(NodeRole::Validator),
            "apps" => Ok(NodeRole::Apps),
            "bootstrap" => Ok(NodeRole::Bootstrap),
            "sentry" => Ok(NodeRole::Sentry),
            "checkpoint" => Ok(NodeRole::Checkpoint),
            _ => Err(anyhow!("Node role not supported")),
        }
    }
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NodeRole::Apps => write!(f, "apps"),
            NodeRole::Validator => write!(f, "validator"),
            NodeRole::Bootstrap => write!(f, "bootstrap"),
            NodeRole::Sentry => write!(f, "sentry"),
            NodeRole::Checkpoint => write!(f, "checkpoint"),
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
    pub labels: BTreeMap<String, String>,
}

impl Machine {
    pub async fn copy_to(&self, file_from: &str, file_to: &str) -> Result<()> {
        let tgt_spec = format!("{0}:{file_to}", &self.name);
        let args = &[
            "compute",
            "scp",
            "--project",
            &self.project_id,
            "--zone",
            &self.zone,
            "--tunnel-through-iap",
            "--strict-host-key-checking=no",
            "--scp-flag=-r",
            file_from,
            &tgt_spec,
        ];
        println!("gcloud {}", args.join(" "));
        zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd("gcloud", args)
            .run()
            .await?;
        Ok(())
    }

    pub async fn run(&self, cmd: &str) -> Result<zqutils::commands::CommandOutput> {
        println!("Running command '{}' in {}", cmd, self.name);
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
                    "--strict-host-key-checking=no",
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
    let mut file_path = std::env::current_dir()?;
    file_path.push(format!("{network_name}.yaml"));
    fs::write(file_path, content).await?;
    Ok(())
}

pub async fn create_provisioning_script(
    provisioning_script: &str,
    file_name: &str,
    role: &str,
    config: &NetworkConfig,
) -> Result<()> {
    // horrific implementation of a rendering engine for the provisioning script used
    // for both first install and upgrade of the ZQ2 network instances.
    // After the proto-testnet launch we can split the provisioning of the infra from the
    // deployment and the configuration of the apps and validator so, we can move it to a proper
    // tera template and remove this.

    let z2_image = &docker_image(
        "zq2",
        config.versions.get("zq2").unwrap_or(&"latest".to_string()),
    )?;

    let otterscan_image = &docker_image(
        "otterscan",
        config
            .versions
            .get("otterscan")
            .unwrap_or(&"latest".to_string()),
    )?;

    let spout_image = &docker_image(
        "spout",
        config
            .versions
            .get("spout")
            .unwrap_or(&"latest".to_string()),
    )?;

    let mut var_map = BTreeMap::<&str, &str>::new();
    var_map.insert("role", role);
    var_map.insert("docker_image", z2_image);
    var_map.insert("otterscan_image", otterscan_image);
    var_map.insert("spout_image", spout_image);

    let ctx = Context::from_serialize(var_map)?;
    let rendered_template = Tera::one_off(provisioning_script, &ctx, false)?;
    let provisioning_script = rendered_template.as_str();

    let mut fh = File::create(file_name).await?;
    fh.write_all(provisioning_script.as_bytes()).await?;
    println!("Provisioning file created: {file_name}");
    Ok(())
}

pub async fn install_or_upgrade(config_file: &str, is_upgrade: bool) -> Result<()> {
    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;

    let mut bootstraps: Vec<Machine> = Vec::new();
    let mut validators: Vec<Machine> = Vec::new();
    let mut apps: Vec<Machine> = Vec::new();
    let mut sentries: Vec<Machine>;
    let mut checkpoints: Vec<Machine>;
    for r in config.roles.clone() {
        let r_name = r.to_string();
        let file_name = &format!("provision_{}.py", r_name);
        create_provisioning_script(
            include_str!("../resources/node_provision.tera.py"),
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
                let project_id = &config.project_id;
                Ok(Machine {
                    project_id: project_id.to_string(),
                    zone: zone.to_string(),
                    name: name.to_string(),
                    labels,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let role_instances: Vec<Machine> = role_instances
            .into_iter()
            .filter(|m| {
                m.labels.get("zq2-network") == Some(&config.name)
                    && m.labels.get("role") == Some(&r_name)
            })
            .collect();

        if r_name == NodeRole::Validator.to_string() {
            validators = role_instances
        } else if r_name == NodeRole::Apps.to_string() {
            apps = role_instances;
            if apps.is_empty() {
                println!("No apps instances found");
            }
        } else if r_name == NodeRole::Bootstrap.to_string() {
            bootstraps = role_instances;
            if bootstraps.is_empty() {
                println!("No bootstraps instances found");
            }
        } else if r_name == NodeRole::Sentry.to_string() {
            sentries = role_instances;
            if sentries.is_empty() {
                println!("No sentries instances found");
            }
        } else if r_name == NodeRole::Checkpoint.to_string() {
            checkpoints = role_instances;
            if checkpoints.is_empty() {
                println!("No checkpoints instances found");
            }
        }
    }

    let node_config = validators::get_chain_spec_config(&config.name).await?;
    let mut bootstrap_config = node_config.clone();
    bootstrap_config
        .as_table_mut()
        .unwrap()
        .remove("external_address");
    bootstrap_config
        .as_table_mut()
        .unwrap()
        .remove("bootstrap_address");

    let mut node_config_path = NamedTempFile::new()?;
    write!(node_config_path, "{}", toml::to_string(&node_config)?)?;

    let mut bootstrap_config_path = NamedTempFile::new()?;
    write!(
        bootstrap_config_path,
        "{}",
        toml::to_string(&bootstrap_config)?
    )?;

    for bootstrap in bootstraps {
        println!("Upgrading bootstrap instance {}", bootstrap.name);
        bootstrap
            .copy_to("./provision_bootstrap.py", "/tmp/provision_node.py")
            .await?;
        bootstrap
            .copy_to(
                bootstrap_config_path.path().as_os_str().to_str().unwrap(),
                "/tmp/config.toml",
            )
            .await?;
        let cmd = "sudo python3 /tmp/provision_node.py";
        let output = bootstrap.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }

        // Check the node is making progress
        if is_upgrade {
            let first_block_number = get_local_block_number(&bootstrap).await?;
            loop {
                let next_block_number = get_local_block_number(&bootstrap).await?;
                println!(
                    "Polled block number at {next_block_number}, waiting for {} more blocks",
                    (first_block_number + 10).saturating_sub(next_block_number)
                );
                if next_block_number >= first_block_number + 10 {
                    break;
                }
            }
        }
    }

    for validator in validators {
        println!("Upgrading validator instance {}", validator.name);
        validator
            .copy_to("./provision_validator.py", "/tmp/provision_node.py")
            .await?;
        validator
            .copy_to(
                node_config_path.path().as_os_str().to_str().unwrap(),
                "/tmp/config.toml",
            )
            .await?;
        let cmd = "sudo python3 /tmp/provision_node.py";
        let output = validator.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }

        // Check the node is making progress
        if is_upgrade {
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
    }

    for app in apps {
        println!("Upgrading app instance {}", app.name);
        app.copy_to("./provision_apps.py", "/tmp/provision_node.py")
            .await?;
        app.copy_to(
            node_config_path.path().as_os_str().to_str().unwrap(),
            "/tmp/config.toml",
        )
        .await?;
        let cmd = "sudo python3 /tmp/provision_node.py";
        let output = app.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }
    }

    Ok(())
}
