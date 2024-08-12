use std::{
    backtrace::{Backtrace, BacktraceStatus},
    fs,
    path::PathBuf,
};

use anyhow::{anyhow, Result};
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
    #[clap(long, short, default_values = ["config.toml"])]
    config_file: Vec<PathBuf>,
    #[clap(long, default_value = "false")]
    log_json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let builder = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_line_number(true)
        .with_ansi(false);
    if args.log_json {
        builder.json().init();
    } else {
        builder.init();
    }

    // Set a panic hook that records the panic as a `tracing` event at the `ERROR` verbosity level.
    std::panic::set_hook(Box::new(|panic| {
        let message = match panic.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match panic.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<dyn Any>",
            },
        };
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");

        let backtrace = Backtrace::capture();
        let backtrace =
            (backtrace.status() == BacktraceStatus::Captured).then(|| backtrace.to_string());

        match (panic.location(), backtrace) {
            (None, None) => {
                tracing::error!(thread_name, message);
            }
            (None, Some(backtrace)) => {
                tracing::error!(thread_name, message, %backtrace);
            }
            (Some(location), None) => {
                tracing::error!(
                    thread_name,
                    message,
                    panic.file = location.file(),
                    panic.line = location.line(),
                    panic.column = location.column(),
                );
            }
            (Some(location), Some(backtrace)) => {
                tracing::error!(
                    thread_name,
                    message,
                    panic.file = location.file(),
                    panic.line = location.line(),
                    panic.column = location.column(),
                    %backtrace,
                );
            }
        }
    }));

    let mut merged_config = toml::Table::new();
    for config_file in args.config_file {
        let config = fs::read_to_string(&config_file)?;
        let config: toml::Table = toml::from_str(&config)?;
        for key in config.keys() {
            if merged_config.contains_key(key) {
                return Err(anyhow!(
                    "configuration conflict: {config_file:?} contained a key {key:?} that was already included in an earlier file"
                ));
            }
        }
        merged_config.extend(config);
    }

    let config: Config = serde::Deserialize::deserialize(merged_config)?;

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
