use clap::{Args, Parser, Subcommand};
use eyre::Result;
use z2lib::plumbing;

#[derive(Parser, Debug)]
#[clap(about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Internal debugging
    Internal(InternalArg),
}

#[derive(Args, Debug)]
struct InternalArg {
    #[clap(subcommand)]
    command: InternalCommand,
}

#[derive(Subcommand, Debug)]
enum InternalCommand {
    /// Just run a local network, to make sure we can.
    Run(RunStruct),
}

#[derive(Args, Debug)]
struct RunStruct {
    config_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Internal(int_cmd) => match &int_cmd.command {
            InternalCommand::Run(ref arg) => {
                plumbing::run_local_net(&arg.config_dir).await?;
                Ok(())
            }
        },
    }
}
