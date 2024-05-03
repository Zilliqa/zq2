use std::{collections::HashSet, env, fmt};

use anyhow::{anyhow, Result};
use clap::{builder::ArgAction, Args, Parser, Subcommand};
use z2lib::plumbing;

#[derive(Parser, Debug)]
#[clap(about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a copy of zilliqa 2
    Run(RunStruct),
    /// Test
    Perf(PerfStruct),
    #[clap(subcommand)]
    /// Deploy
    Deployer(DeployerCommands),
}

#[derive(Subcommand, Debug)]
enum DeployerCommands {
    /// Generate the deployer config file
    New(DeployerConfigStruct),
    /// Perfom the network upgrade
    Upgrade(DeployerConfigStruct),
}

#[derive(Args, Debug)]
pub struct DeployerConfigStruct {
    network_name: Option<String>,
    gcp_project: Option<String>,
    binary_bucket: Option<String>,
    bootstrap_pk: Option<String>,
    config_file: Option<String>,
}

#[derive(Args, Debug)]
struct PerfStruct {
    config_dir: String,

    perf_file: String,
}

// See https://jwodder.github.io/kbits/posts/clap-bool-negate/
#[derive(Args, Debug)]
struct RunStruct {
    config_dir: String,

    #[clap(long)]
    #[clap(default_value = "warn")]
    log_level: LogLevel,

    #[clap(long)]
    debug_modules: Vec<String>,

    #[clap(long)]
    trace_modules: Vec<String>,

    #[clap(long, default_value = "4000")]
    base_port: u16,

    #[clap(long = "restart-network")]
    restart_network: bool,

    #[clap(long="no-otterscan", action= ArgAction::SetFalse)]
    otterscan: bool,
    #[clap(long = "otterscan", overrides_with = "otterscan")]
    _no_otterscan: bool,

    #[clap(long="no-otel", action= ArgAction::SetFalse)]
    otel: bool,
    #[clap(long = "otel", overrides_with = "otel")]
    _no_otel: bool,

    #[clap(long="no-zq2", action= ArgAction::SetFalse)]
    zq2: bool,
    #[clap(long = "zq2", overrides_with = "zq2")]
    _no_zq2: bool,

    #[clap(long="no-spout", action= ArgAction::SetFalse)]
    spout: bool,
    #[clap(long = "spout", overrides_with = "spout")]
    _no_spout: bool,

    #[clap(long="no-mitmweb", action= ArgAction::SetFalse)]
    mitmweb: bool,
    #[clap(long = "mitmweb", overrides_with = "mitmweb")]
    _no_mitmweb: bool,
}

#[derive(Clone, PartialEq, Debug, clap::ValueEnum)]
enum LogLevel {
    Warn,
    Info,
    Debug,
    Trace,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LogLevel::Warn => "warn",
                LogLevel::Info => "info",
                LogLevel::Debug => "debug",
                LogLevel::Trace => "trace",
            }
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Work out the base directory
    let base_dir = match env::var("ZQ2_BASE") {
        Ok(val) => val,
        _ => {
            return Err(anyhow!(
                "Please define ZQ2_BASE or run bin/z2 from the checked out zq2 repository"
            ))
        }
    };
    match &cli.command {
        Commands::Run(ref arg) => {
            let mut to_run: HashSet<plumbing::Components> = HashSet::new();

            if arg.otterscan {
                to_run.insert(plumbing::Components::Otterscan);
            }
            if arg.otel {
                to_run.insert(plumbing::Components::Otel);
            }
            if arg.zq2 {
                to_run.insert(plumbing::Components::ZQ2);
            }
            if arg.spout {
                to_run.insert(plumbing::Components::Spout);
            }
            if arg.mitmweb {
                to_run.insert(plumbing::Components::Mitmweb);
            }

            let keep_old_network = !arg.restart_network;
            plumbing::run_local_net(
                &base_dir,
                arg.base_port,
                &arg.config_dir,
                &arg.log_level.to_string(),
                &arg.debug_modules,
                &arg.trace_modules,
                &to_run,
                keep_old_network,
            )
            .await?;
            Ok(())
        }
        Commands::Perf(ref arg) => {
            plumbing::run_perf_file(&arg.config_dir, &arg.perf_file).await?;
            Ok(())
        }
        Commands::Deployer(deployer_command) => match &deployer_command {
            DeployerCommands::New(ref arg) => {
                let network_name = arg
                    .network_name
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("network_name is a mandatory argument"))?;
                let binary_bucket = arg
                    .binary_bucket
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("binary_bucket is a mandatory argument"))?;
                let gcp_project = arg
                    .gcp_project
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("gcp_project is a mandatory argument"))?;

                plumbing::run_deployer_new(&network_name, &binary_bucket, &gcp_project)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer new command: {}", err)
                    })?;
                Ok(())
            }
            DeployerCommands::Upgrade(ref arg) => {
                let config_file = arg
                    .config_file
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("config_file is a mandatory argument"))?;
                plumbing::run_deployer_upgrade(&config_file)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer upgrade command: {}", err)
                    })?;
                Ok(())
            }
        },
    }
}
