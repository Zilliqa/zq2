extern crate bs58;
use std::{fs, path::PathBuf};
use zilliqa::p2p_node::P2pNode;

use anyhow::Result;
use clap::Parser;

use opentelemetry::runtime;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use tokio::time::Duration;

use zilliqa::{cfg::Config, crypto::SecretKey};

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

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

    let mut node = P2pNode::new(args.secret_key, config.p2p_port, config.bootstrap_address)?;

    for shard_config in config.nodes {
        node.add_shard_node(shard_config.clone()).await?;
    }

    node.start().await
}
