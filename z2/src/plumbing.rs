use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::PathBuf,
    str::FromStr,
};

use alloy::primitives::B256;
use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use tokio::{fs, process::Command};
use zilliqa::crypto::SecretKey;

use crate::{
    chain::{
        self,
        node::{NodePort, NodeRole},
    },
    deployer::Metrics,
    kpi,
    node_spec::{Composition, NodeSpec},
    utils,
};

const DEFAULT_API_URL: &str = "https://api.zq2-devnet.zilliqa.com";

use crate::{collector, components::Component, converter, deployer, docgen, setup, zq1};

pub enum NetworkType {
    Local(Option<NodeSpec>),
    Deployed(chain::Chain),
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetworkType::Local(v) => write!(f, "local {v:?}"),
            NetworkType::Deployed(c) => write!(f, "deployed {c}"),
        }
    }
}

pub async fn print_ports(base_port: u16, base_dir: &str, config_dir: &str) -> Result<()> {
    let setup_obj = setup::Setup::ephemeral(base_port, base_dir, config_dir)?;
    println!("{0}", setup_obj.get_port_map());
    Ok(())
}

pub async fn run_extra_nodes(
    spec: &Composition,
    config_dir: &str,
    base_dir: &str,
    log_spec: &str,
    components: &HashSet<Component>,
    watch: bool,
    checkpoints: &Option<HashMap<u64, zilliqa::cfg::Checkpoint>>,
) -> Result<()> {
    println!("🎈 Loading network configuration from {config_dir} .. ");
    let mut setup_obj = setup::Setup::load(config_dir, log_spec, base_dir, watch).await?;
    // Remove components which are not instanced.
    println!("🎳 Starting nodes {spec:?} .. ");
    let mut collector = collector::Collector::new(log_spec, base_dir).await?;
    for c in Component::in_dependency_order().iter() {
        if components.contains(c) && c.is_instanced() {
            setup_obj
                .run_component(c, &mut collector, spec, checkpoints)
                .await?;
        }
    }
    collector.complete().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_net(
    spec: &NetworkType,
    base_dir: &str,
    base_port: u16,
    config_dir: &str,
    log_spec: &str,
    components: &HashSet<Component>,
    keep_old_network: bool,
    watch: bool,
    checkpoints: &Option<HashMap<u64, zilliqa::cfg::Checkpoint>>,
    secret_key_hex: Option<String>,
) -> Result<()> {
    println!("RUST_LOG = {log_spec}");
    println!("Running network {spec}");
    println!("Create config directory {config_dir} .. ");
    let _ = fs::create_dir(&config_dir).await;
    println!("Generate zq2 configuration .. ");

    let mut setup_obj = match spec {
        NetworkType::Local(local_spec) => {
            let configured = local_spec.clone().map(|x| x.configured);
            setup::Setup::create(
                &configured,
                config_dir,
                base_port,
                log_spec,
                base_dir,
                keep_old_network,
                watch,
            )
            .await?
        }
        NetworkType::Deployed(chain) => {
            if let Some(key) = secret_key_hex {
                setup::Setup::from_named_network(
                    chain, config_dir, base_port, log_spec, base_dir, watch, &key, false,
                )
                .await?
            } else {
                return Err(anyhow!(
                    "Please supply a secret key to join another network"
                ));
            }
        }
    };
    // Generate configuration.
    setup_obj.generate_config().await?;
    println!("{0}", setup_obj.get_port_map());
    println!("Set up collector");
    let mut collector = collector::Collector::new(log_spec, base_dir).await?;
    let actually_start = if let NetworkType::Local(Some(to_start)) = spec {
        &to_start.start
    } else {
        // All of them!
        &setup_obj.config.shape.clone()
    };
    setup_obj.config.composition().check_compatible(actually_start)
        .context(format!("You asked to start nodes {actually_start}, but this wasn't compatible with the network configuration {0} stored in {config_dir}",
        setup_obj.config.composition()))?;
    // Run all components here - not just the ones that are instanced.
    for c in Component::in_dependency_order().iter() {
        if components.contains(c) {
            println!("Start {c}");
            setup_obj
                .run_component(c, &mut collector, actually_start, checkpoints)
                .await?;
        } else {
            println!("Skipping {c}");
        }
    }

    println!("Components running; awaiting termination.");
    collector.complete().await?;
    Ok(())
}

pub async fn run_kpi_collector(config_file: &str) -> Result<()> {
    println!("🦆 Running KPI collector with {config_file} config file...");
    kpi::Kpi::run(&kpi::Config::load(config_file)?).await;
    Ok(())
}

pub async fn run_deployer_install(
    config_file: &str,
    node_selection: bool,
    max_parallel: Option<usize>,
    persistence_url: Option<String>,
    checkpoint_url: Option<String>,
) -> Result<()> {
    println!("🦆 Installing {config_file} .. ");
    deployer::install_or_upgrade(
        config_file,
        false,
        node_selection,
        max_parallel.unwrap_or(50),
        persistence_url,
        checkpoint_url,
    )
    .await?;
    Ok(())
}

pub async fn run_deployer_upgrade(
    config_file: &str,
    node_selection: bool,
    max_parallel: Option<usize>,
) -> Result<()> {
    println!("🦆 Upgrading {config_file} .. ");
    deployer::install_or_upgrade(
        config_file,
        true,
        node_selection,
        max_parallel.unwrap_or(1),
        None,
        None,
    )
    .await?;
    Ok(())
}

pub async fn run_deployer_get_config_file(
    config_file: &str,
    role: NodeRole,
    out: Option<&str>,
) -> Result<()> {
    println!("🦆 Getting nodes config file for {config_file} .. ");
    deployer::get_config_file(config_file, role, out).await?;
    Ok(())
}

pub async fn run_deployer_get_deposit_commands(
    config_file: &str,
    node_selection: bool,
) -> Result<()> {
    println!("🦆 Getting node deposit commands for {config_file} .. ");
    deployer::get_deposit_commands(config_file, node_selection).await?;
    Ok(())
}

pub async fn run_deployer_stakers(config_file: &str) -> Result<()> {
    println!("🦆 Running stakers data for {config_file} .. ");
    deployer::run_stakers(config_file).await?;
    Ok(())
}

pub async fn run_deployer_deposit(config_file: &str, node_selection: bool) -> Result<()> {
    println!("🦆 Running deposit for {config_file} .. ");
    deployer::run_deposit(config_file, node_selection).await?;
    Ok(())
}

pub async fn run_deployer_deposit_top_up(
    config_file: &str,
    node_selection: bool,
    amount: u64,
) -> Result<()> {
    println!("🦆 Running deposit-top-up for {config_file} .. ");
    deployer::run_deposit_top_up(config_file, node_selection, amount).await?;
    Ok(())
}

pub async fn run_deployer_unstake(
    config_file: &str,
    node_selection: bool,
    amount: u64,
) -> Result<()> {
    println!("🦆 Running unstake for {config_file} .. ");
    deployer::run_unstake(config_file, node_selection, amount).await?;
    Ok(())
}

pub async fn run_deployer_withdraw(config_file: &str, node_selection: bool) -> Result<()> {
    println!("🦆 Running withdraw for {config_file} .. ");
    deployer::run_withdraw(config_file, node_selection).await?;
    Ok(())
}

pub async fn run_deployer_rpc(
    method: &str,
    params: &Option<String>,
    config_file: &str,
    timeout: &Option<usize>,
    node_selection: bool,
    port: NodePort,
) -> Result<()> {
    println!("🦆 Running RPC call for {config_file}' .. ");
    deployer::run_rpc_call(
        method,
        params,
        config_file,
        timeout.unwrap_or(30),
        node_selection,
        port,
    )
    .await?;
    Ok(())
}

pub async fn run_deployer_ssh(
    command: Vec<String>,
    config_file: &str,
    node_selection: bool,
) -> Result<()> {
    println!("🦆 Running SSH command for {config_file}' .. ");
    deployer::run_ssh_command(command, config_file, node_selection).await?;
    Ok(())
}

pub async fn run_deployer_backup(config_file: &str, name: Option<String>, zip: bool) -> Result<()> {
    println!("🦆 Backup process for {config_file} .. ");
    deployer::run_backup(config_file, name, zip).await?;
    Ok(())
}

pub async fn run_deployer_restore(
    config_file: &str,
    max_parallel: Option<usize>,
    name: Option<String>,
    zip: bool,
    no_restart: bool,
) -> Result<()> {
    println!("🦆 Restoring process for {config_file} .. ");
    deployer::run_restore(
        config_file,
        max_parallel.unwrap_or(50),
        name,
        zip,
        no_restart,
    )
    .await?;
    Ok(())
}

pub async fn run_deployer_reset(config_file: &str, node_selection: bool) -> Result<()> {
    println!("🦆 Running reset for {config_file} .. ");
    deployer::run_reset(config_file, node_selection).await?;
    Ok(())
}

pub async fn run_deployer_restart(config_file: &str, node_selection: bool) -> Result<()> {
    println!("🦆 Running restart for {config_file} .. ");
    deployer::run_restart(config_file, node_selection).await?;
    Ok(())
}

pub async fn run_deployer_monitor(
    config_file: &str,
    metric: Metrics,
    node_selection: bool,
    follow: bool,
) -> Result<()> {
    println!("🦆 Running monitor for {config_file} .. ");
    deployer::run_monitor(config_file, metric, node_selection, follow).await?;
    Ok(())
}

pub async fn print_depends(_base_dir: &str) -> Result<()> {
    for p in Component::all().iter() {
        let req = setup::Setup::describe_component(p).await?;
        println!("{0} requires:\n {1}", &p, req)
    }
    Ok(())
}

pub async fn update_depends(base_dir: &str, with_ssh: bool) -> Result<()> {
    for p in Component::all().iter() {
        let req = setup::Setup::describe_component(p).await?;
        for repo_spec in &req.repos {
            // If it doesn't exist ..
            let (repo, branch) = utils::split_repo_spec(repo_spec)?;
            let mut dest_dir = PathBuf::from(base_dir);
            dest_dir.push(&repo);
            let repo_base = if with_ssh {
                format!("git@github.com:zilliqa/{0}", &repo)
            } else {
                format!("https://github.com/zilliqa/{0}", &repo)
            };
            if !dest_dir.exists() {
                println!("🌱 Cloning {repo_base} for {p} in {base_dir}/{repo} .. ");
                let mut cmd = Command::new("git");
                cmd.args(["clone", "-b", &branch, &repo_base]);
                cmd.current_dir(base_dir);
                let result = cmd.spawn()?.wait().await?;
                if !result.success() {
                    return Err(anyhow!("Couldn't clone {repo}"));
                }
            } else if !dest_dir.is_dir() {
                return Err(anyhow!("{base_dir}/{repo} is not a directory"));
            }
            // Only do this if there is a remote tracking branch. If not, just ignore the update.
            println!("🌲  Updating {repo_base} for {p} in {base_dir}/{repo} .. ");
            let mut check = Command::new("git");
            check.args(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]);
            check.current_dir(&dest_dir);
            let result = check.spawn()?.wait().await?;
            if result.success() {
                println!("   🪴 there is an upstream. Merging from it .. ");
                let mut cmd = Command::new("git");
                cmd.arg("pull");
                cmd.current_dir(&dest_dir);
                let result = cmd.spawn()?.wait().await?;
                if !result.success() {
                    return Err(anyhow!("Couldn't update {repo} in {base_dir}/{repo}"));
                }
            } else {
                println!("  🌻 no upstream branch; you are probably working here. Skipping");
            }
        }
    }
    Ok(())
}

pub async fn run_persistence_converter(
    zq1_pers_dir: &str,
    zq2_data_dir: &str,
    zq2_config: &str,
    secret_keys: Vec<SecretKey>,
) -> Result<()> {
    println!("🐼 Converting {zq1_pers_dir} into {zq2_data_dir}.. ");
    let zq1_dir = PathBuf::from_str(zq1_pers_dir)?;
    let zq2_dir = PathBuf::from_str(zq2_data_dir)?;
    let config_file = PathBuf::from_str(zq2_config)?;
    let zq2_config = fs::read_to_string(config_file).await?;
    let zq2_config: zilliqa::cfg::Config = toml::from_str(&zq2_config)?;
    let node_config = zq2_config.nodes.first().unwrap();
    let zq2_db = zilliqa::db::Db::new(
        Some(zq2_dir),
        node_config.eth_chain_id,
        // This is None because it makes no difference to the conversion: var is required for fetching ZQ1 blocks and setting their state root hash to zero
        None,
        zilliqa::cfg::DbConfig::default(),
    )?;
    let zq1_db = zq1::Db::new(zq1_dir)?;
    converter::convert_persistence(zq1_db, zq2_db, zq2_config, secret_keys).await?;
    Ok(())
}

pub async fn run_print_txs_in_block(zq1_pers_dir: &str, block_num: u64) -> Result<()> {
    println!("🐼 Printing txns into block {block_num} .. ");
    converter::print_tx_in_block(zq1_pers_dir, block_num).await?;
    Ok(())
}

pub async fn run_print_txs_by_hash(
    zq1_pers_dir: &str,
    block_num: u64,
    tx_hash: B256,
) -> Result<()> {
    println!("🐼 Printing txn with hash {tx_hash} .. ");
    converter::print_tx_by_hash(zq1_pers_dir, block_num, tx_hash).await?;
    Ok(())
}

pub async fn generate_docs(
    base_dir: &str,
    target_dir: &str,
    id_prefix: &Option<String>,
    index_file: &Option<String>,
    in_key_prefix: &Option<String>,
    error_on_mismatch: bool,
    api_url_opt: &Option<String>,
) -> Result<()> {
    // Grotty, but easier than lots of silly Path conversions.
    let scan_dir = format!("{base_dir}/zq2/docs");
    let key_prefix = if let Some(v) = in_key_prefix {
        v.to_string()
    } else {
        "nav".to_string()
    };
    let api_url = if let Some(v) = api_url_opt {
        v.to_string()
    } else {
        DEFAULT_API_URL.to_string()
    };
    let implemented_apis = docgen::get_implemented_jsonrpc_methods()?;
    let docs = docgen::Docs::new(
        &scan_dir,
        target_dir,
        id_prefix,
        index_file,
        &key_prefix,
        &api_url,
        &implemented_apis,
    )?;
    let documented_apis = docs.generate_all().await?;
    let api_table = docs
        .generate_api_table(&documented_apis, &implemented_apis)
        .await?;
    let mut ok = true;
    for api in &api_table {
        match api.status {
            docgen::PageStatus::NotYetDocumented => {
                println!(
                    "{0}",
                    format!("🎲 not documented : {0:?}", &api.method).yellow()
                );
                ok = false;
            }
            docgen::PageStatus::NotYetImplemented => {
                println!(
                    "{0}",
                    format!("🎄 not implemented: {0:?}", &api.method).red()
                );
                ok = false;
            }
            docgen::PageStatus::PartiallyImplemented => {
                println!(
                    "{0}",
                    format!("🍄 partially implemented: {0:?}", &api.method).red()
                );
                ok = false;
            }
            _ => (),
        }
    }
    if ok || !error_on_mismatch {
        Ok(())
    } else {
        Err(anyhow!(
            "There are RPC methods implemented but not documented, or vice versa"
        ))
    }
}
