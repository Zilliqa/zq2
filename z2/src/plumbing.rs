use std::env;

use crate::{collector, otel};
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use tokio::fs;

/// Code for all the z2 commands, so you can invoke it from your own programs.
use crate::setup;

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Components {
    ZQ2,
    Otterscan,
    Otel,
}

impl Components {
    pub fn all() -> HashSet<Components> {
        HashSet::from([Components::ZQ2, Components::Otterscan, Components::Otel])
    }
}

pub async fn run_local_net(
    base_dir: &str,
    config_dir: &str,
    log_level: &str,
    debug_modules: &Vec<String>,
    trace_modules: &Vec<String>,
    components: &HashSet<Components>,
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
    let mut setup_obj = setup::Setup::new(4, config_dir, &log_spec, base_dir)?;
    println!("Set up collector");
    let mut collector = collector::Collector::new(&log_spec, base_dir).await?;
    if components.contains(&Components::ZQ2) {
        println!("Start zq2 .. ");
        setup_obj.run_zq2(&mut collector).await?;
    }
    if components.contains(&Components::Otterscan) {
        println!("Start otterscan .. ");
        if setup_obj.have_otterscan().await? {
            setup_obj.run_otterscan(&mut collector).await?;
        } else {
            return Err(anyhow!(
                "Otterscan was not detected as sibling checkout; cannot run otterscan"
            ));
        }
    }
    collector.complete().await?;
    Ok(())
}
