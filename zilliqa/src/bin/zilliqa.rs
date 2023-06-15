use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use libp2p::{
    gossipsub, identify,
    kad::{store::MemoryStore, Kademlia},
    mdns,
    swarm::NetworkBehaviour,
};
use opentelemetry::runtime;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use tokio::time::Duration;
use twelf::{config, Layer};

use zilliqa::{cfg::Config, crypto::SecretKey, node_launcher::NodeLauncher};

#[config]
#[derive(Parser, Debug)]
struct Args {
    #[clap(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
    #[serde(flatten)]
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

    // let args = Args::parse();
    let args = Args::command().get_matches();
    // TODO: override config path through env variable?
    let config_path = args.get_one::<PathBuf>("config_file");
    println!("Args parsed; config path: {config_path:?}");

    let mut layers: Vec<Layer> = vec![];
    layers.push(Layer::Clap(args.clone()));
    if let Some(path) = config_path {
        if path.exists() {
            layers.push(Layer::Toml(path.clone()));
            println!("Pushing config file layer");
        } else {
            println!("Skipping toml layer...");
        }
    }
    std::env::set_var("ZQ2_ETH_CHAIN_ID", "4000");
    layers.push(Layer::Env(Some("ZQ2_".to_string())));
    // layers.push(Layer::Env(None));

    println!("Layers set up");
    let args = Args::with_layers(&layers)?;

    println!("{args:?}");
    return Ok(());

    let config = args.config;

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
