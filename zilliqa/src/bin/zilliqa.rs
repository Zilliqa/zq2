extern crate bs58;
use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use opentelemetry_sdk::runtime;
use tokio::time::Duration;
use tracing_subscriber::EnvFilter;
use zilliqa::{cfg::Config, crypto::SecretKey, p2p_node::P2pNode};

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
    #[clap(long, default_value = "false")]
    log_json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let builder = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).with_line_number(true);
    if args.log_json {
        builder.json().init();
    } else {
        builder.init();
    }

    let config = if args.config_file.exists() {
        fs::read_to_string(&args.config_file)?
    } else {
        panic!("There needs to be a config file provided");
    };
    let config: Config = toml::from_str(&config)?;
    assert!(
        !config.nodes.is_empty(),
        "At least one shard must be configured"
    );

    if let Some(endpoint) = &config.otlp_collector_endpoint {
        let export_config = ExportConfig {
            endpoint: endpoint.clone(),
            ..Default::default()
        };
        opentelemetry_otlp::new_pipeline()
            .metrics(runtime::Tokio)
            .with_period(Duration::from_secs(10))
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_export_config(export_config),
            )
            .build()?;
    };

    let mut node = P2pNode::new(args.secret_key, config.clone())?;

    node.add_shard_node(config.nodes.first().unwrap().clone())
        .await?;

    node.start().await
}
