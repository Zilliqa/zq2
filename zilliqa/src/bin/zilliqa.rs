use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::Parser;

use libp2p::{
    gossipsub, identify,
    kad::{store::MemoryStore, Kademlia},
    mdns,
    swarm::NetworkBehaviour,
};
use merge::Merge;
use opentelemetry::runtime;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use tokio::time::Duration;

use zilliqa::{cfg::Config, crypto::SecretKey, node_launcher::NodeLauncher};

#[derive(Parser, Debug)]
struct Args {
    #[clap(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
    #[clap(flatten)]
    config: Config,
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

    // Parses the config file (if any); serde fills any missing values with Default::default()
    let toml_config = if args.config_file.exists() {
        toml::from_str::<Config>(&fs::read_to_string(&args.config_file)?)?
    } else {
        Config::default()
    };

    // Merge any remaining default values from clap with the values from either the toml file or
    // Default::default()
    let mut config = args.config;
    config.merge(toml_config);

    let p2p_port = config.p2p_port;
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

    let mut networked_node = NodeLauncher::new(args.secret_key, config.clone())?;

    if !config.disable_json_rpc {
        let handle = networked_node.launch_rpc_server().await?;
        tokio::spawn(handle.stopped());
    }

    networked_node.start_p2p_node(p2p_port).await
}
