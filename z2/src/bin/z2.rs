use std::{
    collections::{HashMap, HashSet},
    env, fmt,
};

use alloy::primitives::B256;
use anyhow::{anyhow, Result};
use clap::{builder::ArgAction, Args, Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};
use z2lib::{
    chain,
    components::Component,
    node_spec::{Composition, NodeSpec},
    plumbing, utils, validators,
};
use zilliqa::crypto::{Hash, SecretKey};

#[derive(Parser, Debug)]
#[clap(about)]
struct Cli {
    /// The subcommand to run
    #[clap(subcommand)]
    command: Commands,
    /// Define the console output verbosity. Default is info. Use -v to enable `debug` and -vv to enable `trace`
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,
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
    /// Group of subcommands to deploy and configure a Zilliqa 2 network
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
    /// Deposit stake amount to validators
    Deposit(DepositStruct),
    Kpi(KpiStruct),
    /// Print out the ports in use (otherwise they scroll off the top too fast)
    Ports(RunStruct),
    /// Start some nodes - this starts all the instanced components (scilla and zq2)
    Nodes(NodesStruct),
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
    /// Install the network defined in the deployer config file
    Install(DeployerInstallArgs),
    /// Update the network defined in the deployer config file
    Upgrade(DeployerUpgradeArgs),
    /// Generate in output the validator config file to join the network
    GetConfigFile(DeployerConfigArgs),
    /// Generate in output the commands to deposit stake amount to all the validators
    GetDepositCommands(DeployerActionsArgs),
    /// Deposit the stake amounts to all the validators
    Deposit(DeployerActionsArgs),
    /// Run RPC calls over the internal network nodes
    Rpc(DeployerRpcArgs),
}

#[derive(Args, Debug)]
pub struct DeployerNewArgs {
    #[clap(long)]
    /// ZQ2 network name
    network_name: Option<String>,
    #[clap(long)]
    /// ZQ2 EVM chain ID
    eth_chain_id: Option<u64>,
    #[clap(long)]
    /// GCP project-id where the network is running
    project_id: Option<String>,
    #[clap(long, value_enum, value_delimiter = ',')]
    /// Virtual Machine roles
    roles: Option<Vec<chain::node::NodeRole>>,
}

#[derive(Args, Debug)]
pub struct DeployerConfigArgs {
    /// The network deployer config file
    config_file: Option<String>,
    /// Node role. Default: validator
    #[clap(long, value_enum)]
    role: Option<chain::node::NodeRole>,
}

#[derive(Args, Debug)]
pub struct DeployerInstallArgs {
    /// The network deployer config file
    config_file: Option<String>,
    /// Enable nodes selection
    #[clap(long)]
    select: bool,
    /// Define the number of nodes to process in parallel. Default: 50
    #[clap(long)]
    max_parallel: Option<usize>,
}

#[derive(Args, Debug)]
pub struct DeployerUpgradeArgs {
    /// The network deployer config file
    config_file: Option<String>,
    /// Enable nodes selection
    #[clap(long)]
    select: bool,
    /// Define the number of nodes to process in parallel. Default: 1
    #[clap(long)]
    max_parallel: Option<usize>,
}

#[derive(Args, Debug)]
pub struct DeployerActionsArgs {
    /// The network deployer config file
    config_file: Option<String>,
    /// Enable nodes selection
    #[clap(long)]
    select: bool,
}

#[derive(Args, Debug)]
pub struct DeployerRpcArgs {
    /// Method to run
    #[clap(long, short, about)]
    method: String,
    /// List of parameters for the method. ie "["string_value", true]"
    #[clap(long, short, about)]
    params: Option<String>,
    /// The network deployer config file
    config_file: String,
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
    #[clap(flatten)]
    convert_type_group: ConvertTypeGroup,
}
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct ConvertTypeGroup {
    #[clap(long)]
    #[arg(default_value_t = false)]
    convert_accounts: bool,
    #[clap(long)]
    #[arg(default_value_t = false)]
    convert_blocks: bool,
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
struct KpiStruct {
    config_file: String,
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

    /// An optional node spec - use node numbers as comma-separated ranges - <network>/<nodes> - eg. 0-3/0-3
    nodespec: Option<String>,

    #[clap(long)]
    #[clap(default_value = "warn")]
    log_level: LogLevel,

    #[clap(long)]
    debug_modules: Vec<String>,

    #[clap(long)]
    trace_modules: Vec<String>,

    #[clap(long, default_value = "4000")]
    base_port: u16,

    /// If --watch is specified, we will auto-reload Zilliqa 2 (but not other programs!) when the source changes.
    #[clap(long, action=ArgAction::SetTrue)]
    watch: bool,

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

    #[clap(long="no-scilla",action=ArgAction::SetFalse)]
    scilla: bool,
    #[clap(long = "scilla", overrides_with = "scilla")]
    _no_scilla: bool,
}

// See https://jwodder.github.io/kbits/posts/clap-bool-negate/
#[derive(Args, Debug)]
struct OnlyStruct {
    config_dir: String,

    /// An optional node spec - <nr_to_run_now>>/<total_nodes_to_provision>
    nodespec: Option<String>,

    #[clap(long)]
    #[clap(default_value = "warn")]
    log_level: LogLevel,

    #[clap(long)]
    debug_modules: Vec<String>,

    #[clap(long)]
    trace_modules: Vec<String>,

    #[clap(long, default_value = "4000")]
    base_port: u16,

    /// If --watch is specified, we will auto-reload Zilliqa 2 (but not other programs!) when the source changes.
    #[clap(long, action=ArgAction::SetTrue)]
    watch: bool,

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

    #[clap(long = "scilla", action = ArgAction::SetTrue)]
    scilla: bool,
}

#[derive(Args, Debug)]
struct JoinStruct {
    /// Specify the ZQ2 chain you want join
    #[clap(long = "chain")]
    chain_name: chain::Chain,
}

#[derive(Args, Debug)]
struct DepositStruct {
    /// Specify the ZQ2 deposit chain
    #[clap(long = "chain")]
    chain_name: chain::Chain,
    /// Specify the Validator Public Key
    #[clap(long)]
    public_key: String,
    /// Specify the Validator PeerId
    #[clap(long)]
    peer_id: String,
    /// Specify the private_key to fund the deposit
    #[clap(long, short)]
    private_key: String,
    /// Specify the stake amount you want provide
    #[clap(long, short)]
    amount: u8,
    /// Specify the staking reward address
    #[clap(long, short)]
    reward_address: String,
    /// Specify the Validator Proof-of-Possession
    #[clap(long)]
    pop_signature: String,
}

#[derive(Args, Debug)]
struct NodesStruct {
    config_dir: String,

    /// This is a composition (/-separated) string which tells us which nodes to start - eg '2,3/4/1,5'
    nodes: String,

    /// From a checkpoint? Syntax is file_name:hash
    checkpoint: Option<String>,

    #[clap(long)]
    #[clap(default_value = "warn")]
    log_level: LogLevel,

    #[clap(long)]
    debug_modules: Vec<String>,

    #[clap(long)]
    trace_modules: Vec<String>,

    /// If --watch is specified, we will auto-reload Zilliqa 2 (but not other programs!) when the source changes.
    #[clap(long, action=ArgAction::SetTrue)]
    watch: bool,

    #[clap(long="no-zq2", action= ArgAction::SetFalse)]
    zq2: bool,
    #[clap(long = "zq2", overrides_with = "zq2")]
    _no_zq2: bool,
    #[clap(long="no-scilla",action=ArgAction::SetFalse)]
    scilla: bool,
    #[clap(long = "scilla", overrides_with = "scilla")]
    _no_scilla: bool,
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

fn nodespec_from_arg(arg: &Option<String>) -> Result<Option<NodeSpec>> {
    if let Some(v) = arg {
        if let Some(x) = NodeSpec::parse(v)? {
            Ok(Some(x))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

fn hash_from_hex(in_str: &str) -> Result<Hash> {
    let bytes = hex::decode(in_str)?;
    let result = Hash::try_from(bytes.as_slice())?;
    Ok(result)
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

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

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
            if arg.scilla {
                to_run.insert(Component::Scilla);
            }

            let keep_old_network = !arg.restart_network;
            let spec = nodespec_from_arg(&arg.nodespec)?;
            let log_spec = utils::compute_log_string(
                &arg.log_level.to_string(),
                &arg.debug_modules,
                &arg.trace_modules,
            )?;
            plumbing::run_local_net(
                &spec,
                &base_dir,
                arg.base_port,
                &arg.config_dir,
                &log_spec,
                &to_run,
                keep_old_network,
                arg.watch,
                &None,
            )
            .await?;
            Ok(())
        }
        Commands::Ports(ref arg) => {
            plumbing::print_ports(arg.base_port, &base_dir, &arg.config_dir).await?;
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
            if arg.scilla {
                to_run.insert(Component::Scilla);
            }

            let keep_old_network = !arg.restart_network;
            let log_spec = utils::compute_log_string(
                &arg.log_level.to_string(),
                &arg.debug_modules,
                &arg.trace_modules,
            )?;
            let spec = nodespec_from_arg(&arg.nodespec)?;
            plumbing::run_local_net(
                &spec,
                &base_dir,
                arg.base_port,
                &arg.config_dir,
                &log_spec,
                &to_run,
                keep_old_network,
                arg.watch,
                &None,
            )
            .await?;
            Ok(())
        }
        Commands::Perf(ref arg) => {
            plumbing::run_perf_file(&arg.config_dir, &arg.perf_file).await?;
            Ok(())
        }
        Commands::Kpi(ref arg) => {
            plumbing::run_kpi_collector(&arg.config_file).await?;
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
                let eth_chain_id = arg
                    .eth_chain_id
                    .ok_or_else(|| anyhow::anyhow!("--eth-chain-id is a mandatory argument"))?;
                plumbing::run_deployer_new(&network_name, eth_chain_id, &project_id, roles)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer new command: {}", err)
                    })?;
                Ok(())
            }
            DeployerCommands::Install(ref arg) => {
                let config_file = arg.config_file.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Provide a configuration file. [--config-file] mandatory argument"
                    )
                })?;
                plumbing::run_deployer_install(&config_file, arg.select, arg.max_parallel)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer install command: {}", err)
                    })?;
                Ok(())
            }
            DeployerCommands::Upgrade(ref arg) => {
                let config_file = arg.config_file.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Provide a configuration file. [--config-file] mandatory argument"
                    )
                })?;
                plumbing::run_deployer_upgrade(&config_file, arg.select, arg.max_parallel)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer upgrade command: {}", err)
                    })?;
                Ok(())
            }
            DeployerCommands::GetConfigFile(ref arg) => {
                let config_file = arg.config_file.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Provide a configuration file. [--config-file] mandatory argument"
                    )
                })?;
                let role = arg.role.clone().unwrap_or(chain::node::NodeRole::Validator);
                plumbing::run_deployer_get_config_file(&config_file, role)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer get-config-file command: {}", err)
                    })?;
                Ok(())
            }
            DeployerCommands::GetDepositCommands(ref arg) => {
                let config_file = arg.config_file.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Provide a configuration file. [--config-file] mandatory argument"
                    )
                })?;
                plumbing::run_deployer_get_deposit_commands(&config_file, arg.select)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!(
                            "Failed to run deployer get-deposit-commands command: {}",
                            err
                        )
                    })?;
                Ok(())
            }
            DeployerCommands::Deposit(ref arg) => {
                let config_file = arg.config_file.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Provide a configuration file. [--config-file] mandatory argument"
                    )
                })?;
                plumbing::run_deployer_deposit(&config_file, arg.select)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer deposit command: {}", err)
                    })?;
                Ok(())
            }
            DeployerCommands::Rpc(ref args) => {
                plumbing::run_rpc_call(&args.method, &args.params, &args.config_file)
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to run deployer rpc command: {}", err)
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
                    arg.convert_type_group.convert_accounts,
                    arg.convert_type_group.convert_blocks,
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
            validators::gen_validator_startup_script(&chain).await?;
            Ok(())
        }
        Commands::Deposit(ref args) => {
            let node =
                validators::Validator::new(&args.peer_id, &args.public_key, &args.pop_signature)?;
            let stake = validators::StakeDeposit::new(
                node,
                args.amount,
                args.chain_name.clone(),
                &args.private_key,
                &args.reward_address,
            )?;
            validators::deposit_stake(&stake).await
        }
        Commands::Nodes(ref args) => {
            let spec = Composition::parse(&args.nodes)?;
            let log_spec = utils::compute_log_string(
                &args.log_level.to_string(),
                &args.debug_modules,
                &args.trace_modules,
            )?;
            let mut to_run: HashSet<Component> = HashSet::new();
            if args.zq2 {
                to_run.insert(Component::ZQ2);
            }
            if args.scilla {
                to_run.insert(Component::Scilla);
            }
            let checkpoints = if let Some(v) = &args.checkpoint {
                let components = v.split(':').collect::<Vec<&str>>();
                if components.len() != 2 {
                    return Err(anyhow!(
                        "Checkpoint spec is not in form <file>:<hash> - {v}"
                    ));
                } else {
                    let mut c = HashMap::new();
                    for id in spec.nodes.keys() {
                        c.insert(
                            *id,
                            zilliqa::cfg::Checkpoint {
                                file: components[0].to_string(),
                                hash: hash_from_hex(components[1])?,
                            },
                        );
                    }
                    Some(c)
                }
            } else {
                None
            };
            plumbing::run_extra_nodes(
                &spec,
                &args.config_dir,
                &base_dir,
                &log_spec,
                &to_run,
                args.watch,
                &checkpoints,
            )
            .await?;
            Ok(())
        }
    }
}
