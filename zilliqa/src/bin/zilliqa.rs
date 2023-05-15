use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::Parser;

use libp2p::{
    gossipsub, identify,
    kad::{store::MemoryStore, Kademlia},
    mdns,
    swarm::NetworkBehaviour,
};
use opentelemetry::runtime;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use tokio::time::Duration;

use zilliqa::{cfg::Config, crypto::SecretKey, node_launcher::NodeLauncher};

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
    #[clap(long, default_value = "false")]
    no_jsonrpc: bool,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    kademlia: Kademlia<MemoryStore>,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let config = if args.config_file.exists() {
        fs::read_to_string(&args.config_file)?
    } else {
        // If the configuration file doesn't exist, we can still construct a default configuration file by parsing an
        // empty TOML document.
        String::new()
    };
    let config: Config = toml::from_str(&config)?;

    let p2p_port = if let Some(port) = config.p2p_port {
        port
    } else {
        0
    };
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

    let mut networked_node = NodeLauncher::new(args.secret_key, config)?;

    if !args.no_jsonrpc {
        let handle = networked_node.launch_rpc_server().await?;
        tokio::spawn(handle.stopped());
    }

    networked_node.start_p2p_node(p2p_port).await
}
