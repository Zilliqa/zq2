use std::sync::Arc;

use anyhow::{anyhow, Result};
use colored::Colorize;
use tokio::{fs, sync::Semaphore, task};

use crate::{
    address::EthereumAddress,
    chain::{
        config::NetworkConfig,
        instance::ChainInstance,
        node::{ChainNode, NodeRole},
    },
    validators,
};

pub async fn new(
    network_name: &str,
    eth_chain_id: u64,
    project_id: &str,
    roles: Vec<NodeRole>,
) -> Result<()> {
    let config = NetworkConfig::new(
        network_name.to_string(),
        eth_chain_id,
        project_id.to_string(),
        roles,
    )
    .await?;
    let content = serde_yaml::to_string(&config)?;
    let mut file_path = std::env::current_dir()?;
    file_path.push(format!("{network_name}.yaml"));
    fs::write(file_path, content).await?;
    Ok(())
}

pub async fn install_or_upgrade(
    config_file: &str,
    is_upgrade: bool,
    only_selected_nodes: bool,
    max_parallel: usize,
) -> Result<()> {
    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;
    let chain = ChainInstance::new(config).await?;
    let mut chain_nodes = chain.nodes().await?;
    let node_names = chain_nodes
        .iter()
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let selected_machines = if !only_selected_nodes {
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

    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;
    let chain = ChainInstance::new(config).await?;
    let mut chain_nodes = chain.nodes().await?;

    chain_nodes.retain(|node| node.role == role);

    if let Some(node) = chain_nodes.first() {
        println!("Config file for a node role {} in {}", role, chain.name());
        println!("---");
        println!("{}", node.get_config_toml()?);
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

pub async fn get_deposit_commands(config_file: &str, only_selected_nodes: bool) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(50)); // Limit to 50 concurrent tasks
    let mut futures = vec![];

    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;
    let chain = ChainInstance::new(config).await?;
    let mut validators = chain.nodes().await?;
    validators.retain(|node| node.role == NodeRole::Validator);

    let validator_names = validators
        .iter()
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let selected_machines = if !only_selected_nodes {
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

    for node in validators {
        let permit = semaphore.clone().acquire_owned().await?;
        let future = task::spawn(async move {
            let result = get_node_deposit_commands(&node).await;
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

pub async fn get_node_deposit_commands(node: &ChainNode) -> Result<()> {
    let genesis_private_key = node.get_genesis_key();
    let private_keys = node.get_private_key().await?;
    let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;
    let reward_private_keys = node.get_wallet_private_key().await?;
    let node_reward_ethereum_address = EthereumAddress::from_private_key(&reward_private_keys)?;

    println!("Validator {}:", node.get_node_name());
    println!("z2 deposit --chain {} \\", node.chain()?);
    println!("\t--peer-id {} \\", node_ethereum_address.peer_id);
    println!("\t--public-key {} \\", node_ethereum_address.bls_public_key);
    println!(
        "\t--pop-signature {} \\",
        node_ethereum_address.bls_pop_signature
    );
    println!("\t--private-key {} \\", genesis_private_key);
    println!(
        "\t--reward-address {} \\",
        node_reward_ethereum_address.address
    );
    println!("\t--amount 100\n");

    Ok(())
}

pub async fn run_deposit(config_file: &str, only_selected_nodes: bool) -> Result<()> {
    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;
    let chain = ChainInstance::new(config.clone()).await?;
    let mut validators = chain.nodes().await?;
    validators.retain(|node| node.role == NodeRole::Validator);

    let validator_names = validators
        .iter()
        .map(|n| n.name().clone())
        .collect::<Vec<_>>();

    let selected_machines = if !only_selected_nodes {
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
        let genesis_private_key = node.get_genesis_key();
        let private_keys = node.get_private_key().await?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;
        let reward_private_keys = node.get_wallet_private_key().await?;
        let node_reward_ethereum_address = EthereumAddress::from_private_key(&reward_private_keys)?;

        println!("Validator {}:", node.get_node_name());

        let validator = validators::Validator::new(
            &node_ethereum_address.peer_id,
            &node_ethereum_address.bls_public_key,
            &node_ethereum_address.bls_pop_signature,
        )?;
        let stake = validators::StakeDeposit::new(
            validator,
            100,
            chain.name().parse()?,
            &genesis_private_key,
            &node_reward_ethereum_address.address,
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

pub async fn run_rpc_call(method: &str, params: &Option<String>, config_file: &str) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(50)); // Limit to 50 concurrent tasks
    let mut futures = vec![];

    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;
    let chain = ChainInstance::new(config).await?;

    // Create a list of chain instances
    let mut machines = chain.machines();
    machines.retain(|m| m.labels.get("role") != Some(&"apps".to_string()));

    println!("Running RPC call on {} nodes", chain.name());
    println!("🦆 Running the RPC call - Method: '{method}' .. ");
    println!(
        "🦆 Params: {} .. ",
        params.clone().unwrap_or("[]".to_owned())
    );

    let column_width = machines
        .iter()
        .map(|m| m.name.len())
        .max()
        .unwrap_or_default();

    for machine in machines {
        let current_method = method.to_owned();
        let current_params = params.to_owned();
        let permit = semaphore.clone().acquire_owned().await?;
        let future = task::spawn(async move {
            let result =
                run_node_rpc_call(&current_method, &current_params, &machine.external_address)
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

async fn run_node_rpc_call(
    method: &str,
    params: &Option<String>,
    endpoint: &str,
) -> Result<String> {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"{}\",\"params\":{}}}",
        method,
        params.clone().unwrap_or("[]".to_string()),
    );

    let args = &[
        "-X",
        "POST",
        "-H",
        "Content-Type:application/json",
        "-H",
        "accept:application/json,*/*;q=0.5",
        "--data",
        &body,
        &format!("http://{endpoint}:4201"),
    ];

    let output = zqutils::commands::CommandBuilder::new()
        .silent()
        .cmd("curl", args)
        .run_for_output()
        .await?;
    if !output.success {
        return Err(anyhow!(
            "getting local block number failed: {:?}",
            output.stderr
        ));
    }

    Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
}
