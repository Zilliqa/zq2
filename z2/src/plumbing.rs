use std::{collections::HashSet, env, path::PathBuf, str::FromStr};

use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use tokio::fs;
use zilliqa::crypto::SecretKey;

use crate::{collector, deployer, otel, otterscan, perf, spout, zq1};
/// Code for all the z2 commands, so you can invoke it from your own programs.
use crate::{converter, docgen, setup};

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Components {
    ZQ2,
    Otterscan,
    Otel,
    Spout,
    Mitmweb,
}

impl Components {
    pub fn all() -> HashSet<Components> {
        HashSet::from([
            Components::ZQ2,
            Components::Otterscan,
            Components::Otel,
            Components::Spout,
            Components::Mitmweb,
        ])
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_local_net(
    base_dir: &str,
    base_port: u16,
    config_dir: &str,
    log_level: &str,
    debug_modules: &Vec<String>,
    trace_modules: &Vec<String>,
    components: &HashSet<Components>,
    keep_old_network: bool,
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
    if components.contains(&Components::Otel) {
        println!("Setting up otel .. ");
        let otel = otel::Otel::new(config_dir)?;
        println!("Write otel configuration .. ");
        otel.write_files().await?;
        println!("Start otel .. ");
        otel.ensure_otel().await?;
    }
    println!("Generate zq2 configuration .. ");
    let mut setup_obj = setup::Setup::new(
        4,
        config_dir,
        &log_spec,
        base_dir,
        base_port,
        keep_old_network,
    )?;
    println!("{0}", setup_obj.get_port_map());
    println!("Set up collector");
    let mut collector = collector::Collector::new(&log_spec, base_dir).await?;
    if components.contains(&Components::ZQ2) {
        println!("Start zq2 .. ");
        setup_obj.run_zq2(&mut collector).await?;
    }

    if components.contains(&Components::Mitmweb) {
        println!("Start mitmweb");
        setup_obj.run_mitmweb(&mut collector).await?;
    }

    if components.contains(&Components::Otterscan) {
        println!("Start otterscan .. ");
        if otterscan::exists(base_dir).await? {
            setup_obj.run_otterscan(&mut collector).await?;
        } else {
            return Err(anyhow!(
                "Otterscan was not detected as sibling checkout; cannot run otterscan"
            ));
        }
    }

    // Wait until the chain is up and running
    setup_obj.wait_for_chain().await?;

    if components.contains(&Components::Spout) {
        println!("Start spout at localhost:5200 .. ");
        if spout::exists(base_dir).await? {
            setup_obj.run_spout(&mut collector).await?;
        } else {
            return Err(anyhow!(
                "{} was not detected",
                spout::get_spout_directory(base_dir)
            ));
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

pub async fn run_deployer_new(
    network_name: &str,
    binary_bucket: &str,
    gcp_project: &str,
) -> Result<()> {
    println!("🦆 Generating the deployer configuration file {network_name}.toml .. ");
    deployer::new(network_name, gcp_project, binary_bucket).await?;
    Ok(())
}

pub async fn run_deployer_upgrade(config_file: &str) -> Result<()> {
    println!("🦆 Upgrading {config_file} .. ");
    deployer::upgrade(config_file).await?;
    Ok(())
}

pub async fn run_persistence_converter(
    zq1_pers_dir: &str,
    zq2_data_dir: &str,
    zq2_config: &str,
    secret_key: SecretKey,
    skip_accounts: bool,
) -> Result<()> {
    println!("🐼 Converting {zq1_pers_dir} into {zq2_data_dir}.. ");
    let zq1_dir = PathBuf::from_str(zq1_pers_dir)?;
    let zq2_dir = PathBuf::from_str(zq2_data_dir)?;
    let config_file = PathBuf::from_str(zq2_config)?;
    let zq1_db = zq1::Db::new(zq1_dir)?;
    let zq2_config = fs::read_to_string(config_file).await?;
    let zq2_config: zilliqa::cfg::Config = toml::from_str(&zq2_config)?;
    let shard_id: u64 = zq2_config
        .nodes
        .first()
        .map(|node| node.eth_chain_id)
        .unwrap_or(0);
    let zq2_db = zilliqa::db::Db::new(Some(zq2_dir), shard_id)?;
    converter::convert_persistence(zq1_db, zq2_db, zq2_config, secret_key, skip_accounts).await?;
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
) -> Result<()> {
    // Grotty, but easier than lots of silly Path conversions.
    let scan_dir = format!("{}/zq2/zilliqa", base_dir);
    let key_prefix = if let Some(v) = in_key_prefix {
        v.to_string()
    } else {
        "nav".to_string()
    };
    let docs = docgen::Docs::new(&scan_dir, target_dir, id_prefix, index_file, &key_prefix)?;
    docs.generate_all().await?;
    Ok(())
}
