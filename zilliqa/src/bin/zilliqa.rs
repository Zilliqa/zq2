extern crate bs58;
use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use std::error::Error;

use libp2p::{gossipsub, identify, kad::{store::MemoryStore, Kademlia}, mdns, PeerId, swarm::NetworkBehaviour};
use opentelemetry::runtime;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use tokio::time::Duration;

use zilliqa::{cfg::Config, crypto::SecretKey, node_launcher::NodeLauncher};
use zilliqa::crypto::NodePublicKey;

/// Parse a single key-value pair
fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
    U: std::str::FromStr,
    U::Err: Error + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
    #[clap(long, default_value = "false")]
    no_jsonrpc: bool,
    #[arg(short, long)]
    genesis_committee: Vec<String>,
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
    let mut config: Config = toml::from_str(&config)?;

    // If the config has no committee to start the network, we need to get this from the args
    // otherwise we have nothing to start with
    if config.genesis_committee.is_empty() {
        if args.genesis_committee.is_empty() {
            panic!("No genesis committee provided via config or command line");
        }

        for item in args.genesis_committee.iter() {

            let parts: Vec<&str> = item.split(",").collect();

            println!("parts: {:?}", parts);
            println!("parts unwrapped: {:?}", hex::decode(parts[1]));

            let pk: NodePublicKey = NodePublicKey::from_hex_string(parts[0]).expect("Invalid public key");
            let id: PeerId = PeerId::from_bytes(&bs58::decode(parts[1]).into_vec().unwrap()).unwrap();
            //let id: PeerId = pk.into();
            //NodePublicKey, PeerId

            config.genesis_committee.push((pk, id));
        }
    }

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

    if !args.no_jsonrpc {
        let handle = networked_node.launch_rpc_server().await?;
        tokio::spawn(handle.stopped());
    }

    networked_node.start_p2p_node(p2p_port).await
}
