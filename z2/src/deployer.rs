use std::{collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use cliclack::MultiProgress;
use colored::Colorize;
use strum::Display;
use tokio::{fs, sync::Semaphore, task};

use crate::{
    address::EthereumAddress,
    chain::{
        config::NetworkConfig,
        instance::ChainInstance,
        node::{ChainNode, NodeRole},
    },
    secret::Secret,
    validators,
};

const VALIDATOR_DEPOSIT_IN_MILLIONS: u8 = 20;
const ZERO_ACCOUNT: &str = "0x0000000000000000000000000000000000000000";

pub async fn new(network_name: &str, eth_chain_id: u64, roles: Vec<NodeRole>) -> Result<()> {
    let config = NetworkConfig::new(network_name.to_string(), eth_chain_id, roles).await?;
    let content = serde_yaml::to_string(&config)?;
    let mut file_path = std::env::current_dir()?;
    file_path.push(format!("{network_name}.yaml"));
    fs::write(file_path, content).await?;
    Ok(())
}

pub async fn install_or_upgrade(
    config_file: &str,
    is_upgrade: bool,
    node_selection: bool,
    max_parallel: usize,
    persistence_url: Option<String>,
    checkpoint_url: Option<String>,
) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let mut chain = ChainInstance::new(config).await?;
    chain.set_persistence_url(persistence_url);
    chain.set_checkpoint_url(checkpoint_url);
    let mut chain_nodes = chain.nodes().await?;

    if chain.checkpoint_url().is_some() {
        chain_nodes.retain(|node| node.role == NodeRole::Validator);
    }

    let node_names = chain_nodes
        .iter()
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let selected_machines = if !node_selection {
        node_names
    } else {
        let mut multi_select = cliclack::multiselect(format!(
            "Select nodes to {}",
            if is_upgrade { "upgrade" } else { "install" }
        ));

        for name in node_names {
            multi_select = multi_select.item(name.clone(), name, "");
        }

        multi_select.interact()?
    };

    let mut bootstrap_nodes = chain_nodes.clone();
    bootstrap_nodes.retain(|node| {
        node.role == NodeRole::Bootstrap && selected_machines.clone().contains(&node.name())
    });

    let mut apps_nodes = chain_nodes.clone();
    apps_nodes.retain(|node| {
        node.role == NodeRole::Apps && selected_machines.clone().contains(&node.name())
    });

    chain_nodes.retain(|node| {
        node.role != NodeRole::Bootstrap
            && node.role != NodeRole::Apps
            && selected_machines.clone().contains(&node.name())
    });

    let _ = execute_install_or_upgrade(bootstrap_nodes, is_upgrade, max_parallel).await;
    let _ = execute_install_or_upgrade(chain_nodes, is_upgrade, max_parallel).await;
    let _ = execute_install_or_upgrade(apps_nodes, is_upgrade, max_parallel).await;

    Ok(())
}

async fn execute_install_or_upgrade(
    nodes: Vec<ChainNode>,
    is_upgrade: bool,
    max_parallel: usize,
) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let mut futures = vec![];

    for node in nodes {
        let permit = semaphore.clone().acquire_owned().await?;
        let future = task::spawn(async move {
            let result = if is_upgrade {
                node.upgrade().await
            } else {
                node.install().await
            };
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    let mut successes = vec![];
    let mut failures = vec![];

    for result in results {
        match result? {
            (node, Ok(())) => successes.push(node.name()),
            (node, Err(err)) => {
                println!("Node {} failed with error: {}", node.name(), err);
                failures.push(node.name());
            }
        }
    }

    for success in successes {
        log::info!("SUCCESS: {}", success);
    }

    for failure in failures {
        log::error!("FAILURE: {}", failure);
    }

    Ok(())
}

pub async fn get_config_file(config_file: &str, role: NodeRole) -> Result<()> {
    if role == NodeRole::Apps {
        log::info!(
            "Config file is not present for nodes with role {}",
            NodeRole::Apps
        );
        return Ok(());
    }

    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let mut chain_nodes = chain.nodes().await?;

    chain_nodes.retain(|node| node.role == role);

    if let Some(node) = chain_nodes.first() {
        let content = node.get_config_toml().await?;
        println!("Config file for a node role {} in {}", role, chain.name());
        println!("---");
        println!("{}", content);
        println!("---");
    } else {
        log::error!(
            "No nodes available in {} for the role {}",
            chain.name(),
            role
        );
    }

    Ok(())
}

pub async fn get_deposit_commands(config_file: &str, node_selection: bool) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(50)); // Limit to 50 concurrent tasks
    let mut futures = vec![];

    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let mut validators = chain.nodes().await?;
    validators.retain(|node| node.role == NodeRole::Validator);

    let validator_names = validators
        .iter()
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let selected_machines = if !node_selection {
        validator_names
    } else {
        let mut multi_select = cliclack::multiselect("Select nodes");

        for name in validator_names {
            multi_select = multi_select.item(name.clone(), name, "");
        }

        multi_select.interact()?
    };

    validators.retain(|node| selected_machines.clone().contains(&node.name()));

    println!(
        "Deposit commands for the validators in the chain {}",
        chain.name()
    );

    let genesis_private_key = chain.genesis_private_key().await?;
    for node in validators {
        let permit = semaphore.clone().acquire_owned().await?;
        let genesis_key = genesis_private_key.clone();
        let future = task::spawn(async move {
            let result = get_node_deposit_commands(&genesis_key, &node).await;
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    for result in results {
        if let (node, Err(err)) = result? {
            log::error!("Node {} failed with error: {}", node.name(), err);
        }
    }

    Ok(())
}

pub async fn get_node_deposit_commands(genesis_private_key: &str, node: &ChainNode) -> Result<()> {
    let private_keys = node.get_private_key().await?;
    let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;

    println!("Validator {}:", node.name());
    println!("z2 deposit --chain {} \\", node.chain()?);
    println!("\t--peer-id {} \\", node_ethereum_address.peer_id);
    println!("\t--public-key {} \\", node_ethereum_address.bls_public_key);
    println!(
        "\t--deposit-auth-signature {} \\",
        node_ethereum_address.secret_key.deposit_auth_signature(
            node.chain_id(),
            node_ethereum_address.secret_key.to_evm_address()
        )
    );
    println!("\t--private-key {} \\", genesis_private_key);
    println!("\t--reward-address {} \\", ZERO_ACCOUNT);
    println!("\t--staking-address {} \\", ZERO_ACCOUNT);
    println!("\t--amount {VALIDATOR_DEPOSIT_IN_MILLIONS}\n");

    Ok(())
}

pub async fn run_deposit(config_file: &str, node_selection: bool) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config.clone()).await?;
    let mut validators = chain.nodes().await?;
    validators.retain(|node| node.role == NodeRole::Validator);

    let validator_names = validators
        .iter()
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let selected_machines = if !node_selection {
        validator_names
    } else {
        let mut multi_select = cliclack::multiselect("Select nodes");

        for name in validator_names {
            multi_select = multi_select.item(name.clone(), name, "");
        }

        multi_select.interact()?
    };

    validators.retain(|node| selected_machines.clone().contains(&node.name()));

    println!(
        "Running stake deposit for the validators in the chain {}",
        chain.name()
    );

    let mut successes = vec![];
    let mut failures = vec![];

    for node in validators {
        let genesis_private_key = chain.genesis_private_key().await?;
        let private_keys = node.get_private_key().await?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;

        println!("Validator {}:", node.name());

        let validator = validators::Validator::new(
            &node_ethereum_address.peer_id,
            &node_ethereum_address.bls_public_key,
            &node_ethereum_address
                .secret_key
                .deposit_auth_signature(
                    node.chain_id(),
                    node_ethereum_address.secret_key.to_evm_address(),
                )
                .to_string(),
        )?;
        let stake = validators::StakeDeposit::new(
            validator,
            VALIDATOR_DEPOSIT_IN_MILLIONS,
            chain.chain()?.get_endpoint()?,
            &genesis_private_key,
            ZERO_ACCOUNT,
            ZERO_ACCOUNT,
        )?;

        let result = validators::deposit_stake(&stake).await;

        match result {
            Ok(()) => successes.push(node.name()),
            Err(err) => {
                println!("Node {} failed with error: {}", node.name(), err);
                failures.push(node.name());
            }
        }
    }

    for success in successes {
        log::info!("SUCCESS: {}", success);
    }

    if !failures.is_empty() {
        for failure in failures {
            log::error!("FAILURE: {}", failure);
        }
        log::error!("Run `z2 deployer get-deposit-commands <chain_file>` to get the deposit command each node");
    }

    Ok(())
}

pub async fn run_rpc_call(
    method: &str,
    params: &Option<String>,
    config_file: &str,
    timeout: usize,
    node_selection: bool,
) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;

    // Create a list of chain instances
    let mut machines = chain.machines();
    machines.retain(|m| m.labels.get("role") != Some(&NodeRole::Apps.to_string()));

    let machine_names = machines.iter().map(|m| m.name.clone()).collect::<Vec<_>>();

    let target_nodes = if node_selection {
        let mut select = cliclack::multiselect("Select target nodes");

        for name in &machine_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut machines = machines.clone();
        machines.retain(|m| selection.contains(&m.name));
        machines
    } else {
        machines.sort_by_key(|machine| machine.name.to_owned());
        machines
    };

    let semaphore = Arc::new(Semaphore::new(50)); // Limit to 50 concurrent tasks
    let mut futures = vec![];

    println!("Running RPC call on {} nodes", chain.name());
    println!("🦆 Running the RPC call - Method: '{method}' .. ");
    println!(
        "🦆 Params: {} .. ",
        params.clone().unwrap_or("[]".to_owned())
    );

    let column_width = target_nodes
        .iter()
        .map(|m| m.name.len())
        .max()
        .unwrap_or_default();

    for machine in target_nodes {
        let current_method = method.to_owned();
        let current_params = params.to_owned();
        let permit = semaphore.clone().acquire_owned().await?;
        let future = task::spawn(async move {
            let result = machine
                .get_rpc_response(&current_method, &current_params, timeout)
                .await;
            drop(permit); // Release the permit when the task is done
            (machine, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    for result in results {
        match result? {
            (machine, Ok(value)) => {
                println!(
                    "{:<width$} => {}",
                    machine.name.bold(),
                    value,
                    width = column_width
                );
            }
            (machine, Err(err)) => {
                log::error!("Node {} failed with error: {}", machine.name, err);
            }
        }
    }

    Ok(())
}

pub async fn run_backup(config_file: &str, filename: &str) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let chain_nodes = chain.nodes().await?;
    let node_names = chain_nodes
        .iter()
        .filter(|n| n.role != NodeRole::Apps)
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let source_node = {
        let mut select = cliclack::select("Select source node");

        for name in &node_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut nodes = chain_nodes.clone();
        nodes.retain(|n| n.name() == selection);
        nodes.first().unwrap().clone()
    };

    source_node.backup_to(filename).await
}

pub async fn run_restore(config_file: &str, filename: &str, max_parallel: usize) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let chain_nodes = chain.nodes().await?;
    let node_names = chain_nodes
        .iter()
        .filter(|n| n.role != NodeRole::Apps)
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let target_nodes = {
        let mut select = cliclack::multiselect("Select target nodes");

        for name in &node_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut nodes = chain_nodes.clone();
        nodes.retain(|n| selection.contains(&n.name()));
        nodes
    };

    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let mut futures = vec![];

    let multi_progress = cliclack::multi_progress("Restoring the nodes data dir".yellow());

    for node in target_nodes {
        let permit = semaphore.clone().acquire_owned().await?;
        let file = filename.to_owned();
        let mp = multi_progress.to_owned();
        let future = task::spawn(async move {
            let result = node.restore_from(&file, &mp).await;
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    multi_progress.stop();

    let mut failures = vec![];

    for result in results {
        if let (node, Err(err)) = result? {
            println!("Node {} failed with error: {}", node.name(), err);
            failures.push(node.name());
        }
    }

    for failure in failures {
        log::error!("FAILURE: {}", failure);
    }

    Ok(())
}

pub async fn run_reset(config_file: &str, node_selection: bool) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let mut chain_nodes = chain.nodes().await?;
    chain_nodes.retain(|node| node.role != NodeRole::Apps);

    let node_names = chain_nodes
        .iter()
        .filter(|n| n.role != NodeRole::Apps)
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let target_nodes = if node_selection {
        let mut select = cliclack::multiselect("Select target nodes");

        for name in &node_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut nodes = chain_nodes.clone();
        nodes.retain(|n| selection.contains(&n.name()));
        nodes
    } else {
        chain_nodes.sort_by_key(|node| node.name());
        chain_nodes
    };

    let semaphore = Arc::new(Semaphore::new(50));
    let mut futures = vec![];

    let multi_progress = cliclack::multi_progress("Resetting the nodes".yellow());

    for node in target_nodes {
        let permit = semaphore.clone().acquire_owned().await?;
        let mp = multi_progress.to_owned();
        let future = task::spawn(async move {
            let result = node.reset(&mp).await;
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    multi_progress.stop();

    let mut failures = vec![];

    for result in results {
        if let (node, Err(err)) = result? {
            println!("Node {} failed with error: {}", node.name(), err);
            failures.push(node.name());
        }
    }

    for failure in failures {
        log::error!("FAILURE: {}", failure);
    }

    Ok(())
}

pub async fn run_restart(config_file: &str, node_selection: bool) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let mut chain_nodes = chain.nodes().await?;
    chain_nodes.retain(|node| node.role != NodeRole::Apps);

    let node_names = chain_nodes
        .iter()
        .filter(|n| n.role != NodeRole::Apps)
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let target_nodes = if node_selection {
        let mut select = cliclack::multiselect("Select target nodes");

        for name in &node_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut nodes = chain_nodes.clone();
        nodes.retain(|n| selection.contains(&n.name()));
        nodes
    } else {
        chain_nodes.sort_by_key(|node| node.name());
        chain_nodes
    };

    let semaphore = Arc::new(Semaphore::new(50));
    let mut futures = vec![];

    let multi_progress = cliclack::multi_progress("Restarting the nodes".yellow());

    for node in target_nodes {
        let permit = semaphore.clone().acquire_owned().await?;
        let mp = multi_progress.to_owned();
        let future = task::spawn(async move {
            let result = node.restart(&mp).await;
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    multi_progress.stop();

    let mut failures = vec![];

    for result in results {
        if let (node, Err(err)) = result? {
            println!("Node {} failed with error: {}", node.name(), err);
            failures.push(node.name());
        }
    }

    for failure in failures {
        log::error!("FAILURE: {}", failure);
    }

    Ok(())
}

pub async fn run_generate_genesis_key(config_file: &str, force: bool) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;

    let multi_progress = cliclack::multi_progress("Generating the genesis key".yellow());

    let secret_name = &format!("{}-genesis-key", chain.name());
    let mut labels = BTreeMap::<String, String>::new();
    labels.insert("role".to_string(), "genesis".to_owned());
    labels.insert("zq2-network".to_string(), chain.name());
    let result = generate_secret(
        &multi_progress,
        secret_name,
        labels,
        chain.chain()?.get_project_id()?,
        force,
    )
    .await;

    multi_progress.stop();

    result
}

pub async fn run_generate_private_keys(
    config_file: &str,
    node_selection: bool,
    force: bool,
) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;

    // Create a list of instances
    let mut machines = chain.machines();
    machines.retain(|m| m.labels.get("role") != Some(&NodeRole::Apps.to_string()));

    let machine_names = machines.iter().map(|m| m.name.clone()).collect::<Vec<_>>();

    let target_nodes = if node_selection {
        let mut select = cliclack::multiselect("Select target nodes");

        for name in &machine_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut machines = machines.clone();
        machines.retain(|m| selection.contains(&m.name));
        machines
    } else {
        machines.sort_by_key(|machine| machine.name.to_owned());
        machines
    };

    let semaphore = Arc::new(Semaphore::new(50));
    let mut futures = vec![];

    let multi_progress = cliclack::multi_progress("Generating the node private keys".yellow());

    for node in target_nodes {
        let permit = semaphore.clone().acquire_owned().await?;
        let mp = multi_progress.to_owned();
        let chain_name = chain.name();
        let role = node
            .labels
            .get("role")
            .unwrap_or_else(|| panic!("The machine {} has no label role", node.name))
            .clone();
        let future = task::spawn(async move {
            let secret_name = &format!("{}-pk", node.clone().name);
            let project_id = &node.clone().project_id;
            let mut labels = BTreeMap::<String, String>::new();
            labels.insert("is-private-key".to_string(), "true".to_string());
            labels.insert("role".to_string(), role);
            labels.insert("zq2-network".to_string(), chain_name);
            labels.insert("node-name".to_string(), node.clone().name);
            let result = generate_secret(&mp, secret_name, labels, project_id, force).await;
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    multi_progress.stop();

    let mut failures = vec![];

    for result in results {
        if let (machine, Err(err)) = result? {
            println!("Node {} failed with error: {}", machine.name, err);
            failures.push(machine.name);
        }
    }

    for failure in failures {
        log::error!("FAILURE: {}", failure);
    }

    Ok(())
}

async fn generate_secret(
    multi_progress: &MultiProgress,
    name: &str,
    labels: BTreeMap<String, String>,
    project_id: &str,
    force: bool,
) -> Result<()> {
    let progress_bar = multi_progress.add(cliclack::progress_bar(if force { 4 } else { 3 }));
    let mut filters = Vec::<String>::new();
    for (k, v) in labels.clone() {
        filters.push(format!("labels.{}={}", k, v));
    }
    let filters = &filters.join(" AND ");

    // Retrieve existing secret
    progress_bar.start(format!("{}: Retrieving existing secret", name));
    let mut secrets = Secret::get_secrets(project_id, filters).await?;
    if secrets.len() > 1 {
        return Err(anyhow!(
            "Error: found multiple secrets with the filter {filters}"
        ));
    }
    progress_bar.inc(1);

    // If force and present delete the old secret before
    if !secrets.is_empty() && force {
        progress_bar.start(format!("{}: Deleting existing secret", name));
        secrets[0].delete().await?;
        secrets.clear();
        progress_bar.inc(1);
    }

    // Create secret if does not exist
    progress_bar.start(format!("{}: Create secret if does not exist", name));
    if secrets.is_empty() {
        let secret = Secret::create(project_id, name, labels).await?;
        secrets.push(secret);
    }
    progress_bar.inc(1);

    // Create a version if does not exist or replace it
    progress_bar.start(format!(
        "{}: Creating new secret version if not exist",
        name
    ));
    let secret_value = &Secret::generate_random_secret().await?;

    if let Some(error) = secrets[0].value().await.err() {
        if error.to_string().contains("has no versions") {
            secrets[0].add_version(secret_value).await?;
        }
    }
    progress_bar.inc(1);

    // Process completed
    progress_bar.stop(format!("{} {}: Secret created", "✔".green(), name));

    Ok(())
}

#[derive(Clone, Debug, Display, ValueEnum)]
pub enum ApiOperation {
    #[value(name = "attach")]
    Attach,
    #[value(name = "detach")]
    Detach,
}

pub async fn run_api_operation(config_file: &str, operation: ApiOperation) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let chain_nodes = chain.nodes().await?;
    let node_names = chain_nodes
        .iter()
        .filter(|n| n.role == NodeRole::Api)
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let target_nodes = {
        let mut select = cliclack::multiselect("Select target nodes");

        for name in &node_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut nodes = chain_nodes.clone();
        nodes.retain(|n| selection.contains(&n.name()));
        nodes
    };

    let semaphore = Arc::new(Semaphore::new(50));
    let mut futures = vec![];

    let multi_progress =
        cliclack::multi_progress(format!("Running API operation '{}'", operation).yellow());

    for node in target_nodes {
        let permit = semaphore.clone().acquire_owned().await?;
        let operation = operation.to_owned();
        let mp = multi_progress.to_owned();
        let future = task::spawn(async move {
            let result = match operation {
                ApiOperation::Attach => node.api_attach(&mp).await,
                ApiOperation::Detach => node.api_detach(&mp).await,
            };
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    multi_progress.stop();

    let mut failures = vec![];

    for result in results {
        if let (node, Err(err)) = result? {
            println!("Node {} failed with error: {}", node.name(), err);
            failures.push(node.name());
        }
    }

    for failure in failures {
        log::error!("FAILURE: {}", failure);
    }

    Ok(())
}

pub async fn run_block_number(config_file: &str, node_selection: bool, follow: bool) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let mut chain_nodes = chain.nodes().await?;
    chain_nodes.retain(|node| node.role != NodeRole::Apps);

    let node_names = chain_nodes
        .iter()
        .filter(|n| n.role != NodeRole::Apps)
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let target_nodes = if node_selection {
        let mut select = cliclack::multiselect("Select target nodes");

        for name in &node_names {
            select = select.item(name.clone(), name, "");
        }

        let selection = select.interact()?;
        let mut nodes = chain_nodes.clone();
        nodes.retain(|n| selection.contains(&n.name()));
        nodes
    } else {
        chain_nodes.sort_by_key(|node| node.name());
        chain_nodes
    };

    let semaphore = Arc::new(Semaphore::new(50));
    let mut futures = vec![];

    let multi_progress = indicatif::MultiProgress::new();

    for node in target_nodes {
        let permit = semaphore.clone().acquire_owned().await?;
        let mp = multi_progress.to_owned();
        let future = task::spawn(async move {
            let result = node.get_block(&mp, follow).await;
            drop(permit); // Release the permit when the task is done
            (node, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    let mut failures = vec![];

    for result in results {
        if let (node, Err(err)) = result? {
            println!("Node {} failed with error: {}", node.name(), err);
            failures.push(node.name());
        }
    }

    for failure in failures {
        log::error!("FAILURE: {}", failure);
    }

    Ok(())
}
