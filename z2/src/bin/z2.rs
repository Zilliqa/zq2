use std::fmt;

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};
use std::env;
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
            plumbing::run_local_net(
                &base_dir,
                &arg.config_dir,
                &arg.log_level.to_string(),
                &arg.debug_modules,
                &arg.trace_modules,
            )
            .await?;
            Ok(())
        }
    }
}
