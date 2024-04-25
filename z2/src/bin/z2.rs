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

            plumbing::run_local_net(
                &base_dir,
                arg.base_port,
                &arg.config_dir,
                &arg.log_level.to_string(),
                &arg.debug_modules,
                &arg.trace_modules,
                &to_run,
            )
            .await?;
            Ok(())
        }
    }
}
