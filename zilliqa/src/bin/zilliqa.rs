use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::{CommandFactory, Parser};

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

use zilliqa::{
    cfg::{Config, ConfigOpt},
    crypto::SecretKey,
    node_launcher::NodeLauncher,
};

#[derive(Parser, Debug)]
struct Args {
    #[clap(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
    #[clap(flatten)]
    config: ConfigOpt,
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
    println!("Args parsed; config path: {:?}", args.config_file);

    let toml_config = if args.config_file.exists() {
        println!("Parsing toml file");
        toml::from_str::<ConfigOpt>(&fs::read_to_string(&args.config_file)?)?
    } else {
        println!("Skipping toml file");
        ConfigOpt::default()
    };

    println!("{args:?}");
    let mut config = args.config;
    config.merge(toml_config);

    println!("{config:?}");
    return Ok(());

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

    let mut networked_node = NodeLauncher::new(args.secret_key, config)?;

    if !config.disable_json_rpc {
        let handle = networked_node.launch_rpc_server().await?;
        tokio::spawn(handle.stopped());
    }

    networked_node.start_p2p_node(p2p_port).await
}
