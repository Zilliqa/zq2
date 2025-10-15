use std::{
    backtrace::{Backtrace, BacktraceStatus},
    fs,
    path::PathBuf,
};

use anyhow::{Result, anyhow};
use clap::Parser;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use opentelemetry_sdk::metrics::PeriodicReader;
use tracing_subscriber::EnvFilter;
use zilliqa::{cfg::Config, crypto::SecretKey, p2p_node::P2pNode};

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = secret_key_from_cli_or_env, required = false, default_value = "")]
    secret_key: SecretKey,
    #[clap(long, short, default_values = ["config.toml"])]
    config_file: Vec<PathBuf>,
    #[clap(long, default_value = "false")]
    log_json: bool,
}

/// The cli argument overrides the SECRET_KEY environment variable.
fn secret_key_from_cli_or_env(secret_key: &str) -> Result<SecretKey> {
    if secret_key.is_empty() {
        std::env::var("SECRET_KEY")
            .map_or_else(|e| Err(anyhow!(e.to_string())), |k| SecretKey::from_hex(&k))
    } else {
        SecretKey::from_hex(secret_key)
    }
}

async fn app(args: Args, config: Config) -> Result<()> {
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

    if let Some(endpoint) = &config.otlp_collector_endpoint {
        let export_config = ExportConfig {
            endpoint: Some(endpoint.clone()),
            ..Default::default()
        };
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_export_config(export_config)
            .build()?;
        let reader = PeriodicReader::builder(exporter).build();
        let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(reader)
            .build();
        opentelemetry::global::set_meter_provider(provider);
    };

    let mut node = P2pNode::new(args.secret_key, config.clone())?;

    node.add_shard_node(
        config.nodes.first().unwrap().clone(),
        config.redis_address.clone(),
    )
    .await?;

    node.start().await
}

fn main() -> Result<()> {
    let args = Args::parse();

    let builder = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_line_number(true);
    if args.log_json {
        builder.json().init();
    } else {
        builder.init();
    }

    let mut merged_config = toml::Table::new();
    for config_file in &args.config_file {
        let config = fs::read_to_string(config_file)?;
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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(config.slow_rpc_queries_handlers_count)
        .enable_all()
        .build()?;

    rt.block_on(async { app(args, config).await })
}
