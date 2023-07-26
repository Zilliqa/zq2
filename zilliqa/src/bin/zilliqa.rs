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
use tokio::{task::JoinSet, time::Duration};

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

    // TODO: proper multi-node config!!
    // let mut shard_config = config.clone();
    // // shard_config.p2p_port += 1;
    // shard_config.json_rpc_port += 1;
    // shard_config.eth_chain_id += 1;

    println!("a");
    let mut main_shard_node = NodeLauncher::new(args.secret_key, config)?;
    // let mut shard_node = NodeLauncher::new(args.secret_key, shard_config)?;

    println!("b");
    if !args.no_jsonrpc {
        let handle = main_shard_node.launch_rpc_server().await?;
        tokio::spawn(handle.stopped());

        // println!("c");
        // let handle = shard_node.launch_rpc_server().await?;
        // tokio::spawn(handle.stopped());
        // println!("d");
    }

    let mut task_set = JoinSet::new();
    task_set.spawn(async move { main_shard_node.start_p2p_node().await });
    println!("e");
    // task_set.spawn(async move { shard_node.start_p2p_node().await });
    println!("f");
    while let Some(res) = task_set.join_next().await {
        println!("__g");
        println!("{:?}", res);
        res??;
        println!("__g1");
    }
    println!("h");
    Ok(())
}
