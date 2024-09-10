#![allow(unused_imports)]
use std::{collections::HashSet, env, path::PathBuf, str::FromStr};

use alloy::primitives::B256;
use anyhow::{anyhow, Result};
use colored::Colorize;
use tokio::{fs, process::Command};
use zilliqa::crypto::SecretKey;

use crate::{kpi, utils};

const DEFAULT_API_URL: &str = "https://api.zq2-devnet.zilliqa.com";

use crate::{
    collector, components::Component, converter, deployer, deployer::NodeRole, docgen, otel,
    otterscan, perf, setup, spout, zq1,
};

#[allow(clippy::too_many_arguments)]
pub async fn run_local_net(
    base_dir: &str,
    base_port: u16,
    config_dir: &str,
    log_level: &str,
    debug_modules: &Vec<String>,
    trace_modules: &Vec<String>,
    components: &HashSet<Component>,
    keep_old_network: bool,
    watch: bool,
) -> Result<()> {
    // Now build the log string. If there already was one, use that ..
    let log_var = env::var("RUST_LOG");
    let log_spec = match log_var {
        Ok(val) => {
            println!("Using RUST_LOG from environment");
            val
        }
        _ => {
            let mut val = log_level.to_string();
            for i in debug_modules {
                val.push_str(&format!(",{i}=debug"));
            }
            for i in trace_modules {
                val.push_str(&format!(",{i}=trace"));
            }
            val.push_str(",opentelemetry=trace,opentelemetry_otlp=trace");
            val
        }
    };
    println!("RUST_LOG = {log_spec}");
    println!("Create config directory .. ");
    let _ = fs::create_dir(&config_dir).await;
    println!("Generate zq2 configuration .. ");
    let mut setup_obj = setup::Setup::new(
        4,
        config_dir,
        &log_spec,
        base_dir,
        base_port,
        keep_old_network,
        watch,
    )?;
    println!("{0}", setup_obj.get_port_map());
    println!("Set up collector");
    let mut collector = collector::Collector::new(&log_spec, base_dir).await?;
    // Iterate through the components in dependency order.
    for c in Component::in_dependency_order().iter() {
        if components.contains(c) {
            println!("Start {c}");
            setup_obj.run_component(c, &mut collector).await?;
        } else {
            println!("Skipping {c}");
        }
    }

    collector.complete().await?;
    Ok(())
}

pub async fn run_perf_file(_base_dir: &str, config_file: &str) -> Result<()> {
    let perf = perf::Perf::from_file(config_file)?;
    let mut rng = perf.make_rng()?;
    println!("🦆 Running {config_file} .. ");
    perf.run(&mut rng).await?;
    Ok(())
}

pub async fn run_kpi_collector(config_file: &str) -> Result<()> {
    println!("🦆 Running KPI collector with {config_file} config file...");
    kpi::Kpi::run(&kpi::Config::load(config_file)?).await;
    Ok(())
}

pub async fn run_deployer_new(
    network_name: &str,
    eth_chain_id: u64,
    project_id: &str,
    roles: Vec<NodeRole>,
) -> Result<()> {
    println!("🦆 Generating the deployer configuration file {network_name}.yaml .. ");
    deployer::new(network_name, eth_chain_id, project_id, roles).await?;
    Ok(())
}

pub async fn run_deployer_install(config_file: &str) -> Result<()> {
    println!("🦆 Installing {config_file} .. ");
    deployer::install_or_upgrade(config_file, false).await?;
    Ok(())
}

pub async fn run_deployer_upgrade(config_file: &str) -> Result<()> {
    println!("🦆 Upgrading {config_file} .. ");
    deployer::install_or_upgrade(config_file, true).await?;
    Ok(())
}

pub async fn run_deployer_get_deposit_commands(config_file: &str) -> Result<()> {
    println!("🦆 Getting node deposit commands for {config_file} .. ");
    deployer::get_deposit_commands(config_file).await?;
    Ok(())
}

pub async fn run_deployer_deposit(config_file: &str) -> Result<()> {
    println!("🦆 Running deposit for {config_file} .. ");
    deployer::run_deposit(config_file).await?;
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
    secret_key: SecretKey,
    convert_accounts: bool,
    convert_blocks: bool,
) -> Result<()> {
    println!("🐼 Converting {zq1_pers_dir} into {zq2_data_dir}.. ");
    let zq1_dir = PathBuf::from_str(zq1_pers_dir)?;
    let zq2_dir = PathBuf::from_str(zq2_data_dir)?;
    let config_file = PathBuf::from_str(zq2_config)?;
    let zq2_config = fs::read_to_string(config_file).await?;
    let zq2_config: zilliqa::cfg::Config = toml::from_str(&zq2_config)?;
    let shard_id: u64 = zq2_config
        .nodes
        .first()
        .map(|node| node.eth_chain_id)
        .unwrap_or(0);
    let zq2_db = zilliqa::db::Db::new(Some(zq2_dir), shard_id)?;
    let zq1_db = zq1::Db::new(zq1_dir)?;
    converter::convert_persistence(
        zq1_db,
        zq2_db,
        zq2_config,
        secret_key,
        convert_accounts,
        convert_blocks,
    )
    .await?;
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
    let scan_dir = format!("{}/zq2/docs", base_dir);
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
