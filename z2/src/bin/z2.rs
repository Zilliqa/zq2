use std::{collections::HashSet, env, fmt};

use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use clap::{builder::ArgAction, Args, Parser, Subcommand};
use z2lib::{components::Component, deployer, plumbing, validators};
use zilliqa::crypto::SecretKey;

#[derive(Parser, Debug)]
#[clap(about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a copy of Zilliqa 2
    Run(RunStruct),
    /// Run only some components of Zilliqa 2
    Only(OnlyStruct),
    /// Test
    Perf(PerfStruct),
    #[clap(subcommand)]
    /// Deploy Zilliqa 2
    Deployer(DeployerCommands),
    #[clap(subcommand)]
    /// Convert Zilliqa 1 to Zilliqa 2 persistnce
    Converter(ConverterCommands),
    /// Generate documentation
    DocGen(DocStruct),
    /// Print the list of sibling repositories for z2 start
    #[clap(subcommand)]
    Depends(DependsCommands),
    /// Join a ZQ2 network
    Join(JoinStruct),
}

#[derive(Subcommand, Debug)]
enum DependsCommands {
    /// Print the repos required.
    Print,
    /// Update the required repos
    Update(DependsUpdateOptions),
}

#[derive(Args, Debug)]
pub struct DependsUpdateOptions {
    /// When checking out repositories, should we use ssh? This requires authentication, but is useful for those in Zilliqa.
    #[clap(long,action=ArgAction::SetTrue)]
    with_ssh: bool,
}

#[derive(Subcommand, Debug)]
enum DeployerCommands {
    /// Generate the deployer config file
    New(DeployerNewArgs),
    /// Perfom the network upgrade
    Upgrade(DeployerUpgradeArgs),
}

#[derive(Args, Debug)]
pub struct DeployerNewArgs {
    #[clap(long)]
    /// ZQ2 network name
    network_name: Option<String>,
    #[clap(long)]
    /// GCP project-id where the network is running
    project_id: Option<String>,
    #[clap(long, value_enum, value_delimiter = ',')]
    /// Virtual Machine roles
    roles: Option<Vec<deployer::NodeRole>>,
}

#[derive(Args, Debug)]
pub struct DeployerUpgradeArgs {
    config_file: Option<String>,
}
#[derive(Subcommand, Debug)]
enum ConverterCommands {
    /// Convert Zilliqa 1 to Zilliqa 2 persistence format.
    Convert(ConvertConfigStruct),
    /// Print the transaction in a given block
    PrintTransactionsInBlock(ConverterPrintTransactionConfigStruct),
    /// Print transaction by Hash
    PrintTransactionConverter(ConverterPrintTransactionConfigStruct),
}

#[derive(Args, Debug)]
struct ConvertConfigStruct {
    zq1_persistence_directory: String,
    zq2_data_dir: String,
    zq2_config_file: String,
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long)]
    skip_accounts: bool,
}

#[derive(Args, Debug)]
struct ConverterPrintTransactionConfigStruct {
    zq1_persistence_directory: String,
    block_number: u64,
    txn_hash: Option<B256>,
}

#[derive(Args, Debug)]
struct PerfStruct {
    config_dir: String,

    perf_file: String,
}

#[derive(Args, Debug)]
struct DocStruct {
    /// Where should we write the resulting documentation?
    target_dir: String,

    /// id prefix, if there is one.
    #[clap(long)]
    id_prefix: Option<String>,

    /// Modify this index file
    #[clap(long)]
    index_file: Option<String>,

    /// Key prefix in the index file.
    #[clap(long)]
    key_prefix: Option<String>,

    /// Should we fail with an error if there is a mismatch between docs and implementation
    #[clap(long)]
    fail_on_mismatch: bool,

    /// API url to show in the generated documentation
    #[clap(long)]
    api_url: Option<String>,
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

    #[clap(long="no-docs",action=ArgAction::SetFalse)]
    docs: bool,
    #[clap(long = "docs", overrides_with = "docs")]
    _no_docs: bool,
}

// See https://jwodder.github.io/kbits/posts/clap-bool-negate/
#[derive(Args, Debug)]
struct OnlyStruct {
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

    #[clap(long = "otterscan", action =ArgAction::SetTrue)]
    otterscan: bool,

    #[clap(long = "otel", action = ArgAction::SetTrue)]
    otel: bool,

    #[clap(long = "zq2", action = ArgAction::SetTrue)]
    zq2: bool,

    #[clap(long = "spout", action = ArgAction::SetTrue)]
    spout: bool,

    #[clap(long = "mitmweb", action = ArgAction::SetTrue)]
    mitmweb: bool,

    #[clap(long = "docs", action = ArgAction::SetTrue)]
    docs: bool,

}

#[derive(Args, Debug)]
struct JoinStruct {
    /// Specify the ZQ2 chain you want join
    chain_name: String,
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
    // Work out the base directory
    let base_dir = match env::var("ZQ2_BASE") {
        Ok(val) => {
            let canon = tokio::fs::canonicalize(val).await?;
            zqutils::utils::string_from_path(&canon)?
        }
        _ => {
            return Err(anyhow!(
                "Please run scripts/z2 from the checked out zq2 repository which sets ZQ2_BASE"
            ))
        }
    };
    let cli = Cli::parse();

    match &cli.command {
        Commands::Only(ref arg) => {
            let mut to_run: HashSet<Component> = HashSet::new();

            if arg.otterscan {
                to_run.insert(Component::Otterscan);
            }
            if arg.otel {
                to_run.insert(Component::Otel);
            }
            if arg.zq2 {
                to_run.insert(Component::ZQ2);
            }
            if arg.spout {
                to_run.insert(Component::Spout);
            }
            if arg.mitmweb {
                to_run.insert(Component::Mitmweb);
            }
            if arg.docs {
                to_run.insert(Component::Docs);
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
        Commands::Run(ref arg) => {
            let mut to_run: HashSet<Component> = HashSet::new();

            if arg.otterscan {
                to_run.insert(Component::Otterscan);
            }
            if arg.otel {
                to_run.insert(Component::Otel);
            }
            if arg.zq2 {
                to_run.insert(Component::ZQ2);
            }
            if arg.spout {
                to_run.insert(Component::Spout);
            }
            if arg.mitmweb {
                to_run.insert(Component::Mitmweb);
            }
            if arg.docs {
                to_run.insert(Component::Docs);
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
                    .ok_or_else(|| anyhow::anyhow!("--network-name is a mandatory argument"))?;
                let project_id = arg
                    .project_id
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--project-id is a mandatory argument"))?;
                let roles = arg
                    .roles
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--roles is a mandatory argument"))?;

                plumbing::run_deployer_new(&network_name, &project_id, roles)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer new command: {}", err)
                    })?;
                Ok(())
            }
            DeployerCommands::Upgrade(ref arg) => {
                let config_file = arg.config_file.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Provide a configuration file. [--config-file] mandatory argument"
                    )
                })?;
                plumbing::run_deployer_upgrade(&config_file)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer upgrade command: {}", err)
                    })?;
                Ok(())
            }
        },
        Commands::Converter(converter_command) => match &converter_command {
            ConverterCommands::Convert(ref arg) => {
                plumbing::run_persistence_converter(
                    &arg.zq1_persistence_directory,
                    &arg.zq2_data_dir,
                    &arg.zq2_config_file,
                    arg.secret_key,
                    arg.skip_accounts,
                )
                .await?;
                Ok(())
            }
            ConverterCommands::PrintTransactionsInBlock(ref arg) => {
                plumbing::run_print_txs_in_block(&arg.zq1_persistence_directory, arg.block_number)
                    .await?;
                Ok(())
            }
            ConverterCommands::PrintTransactionConverter(ref _arg) => {
                unimplemented!();
            }
        },
        Commands::DocGen(ref arg) => {
            plumbing::generate_docs(
                &base_dir,
                &arg.target_dir,
                &arg.id_prefix,
                &arg.index_file,
                &arg.key_prefix,
                arg.fail_on_mismatch,
                &arg.api_url,
            )
            .await?;
            Ok(())
        }
        Commands::Depends(ref rs) => match rs {
            DependsCommands::Print => plumbing::print_depends(&base_dir).await,
            DependsCommands::Update(ref opts) => {
                plumbing::update_depends(&base_dir, opts.with_ssh).await
            }
        },
        Commands::Join(ref args) => {
            let chain = validators::ChainConfig::new(&args.chain_name).await?;
            println!("{:?}", chain);
            Ok(())
        }
    }
}
