use std::{collections::HashMap, ops::Add, sync::Arc};

use alloy::{
    primitives::{Bytes, U256},
    providers::Provider as _,
    rpc::types::TransactionRequest,
};
use anyhow::Result;
use clap::ValueEnum;
use colored::Colorize;
use tokio::{sync::Semaphore, task};
use zilliqa::{crypto::SecretKey, exec::BLESSED_TRANSACTIONS};

use crate::{
    address::EthereumAddress,
    chain::{
        Chain,
        config::NetworkConfig,
        instance::ChainInstance,
        node::{ChainNode, NodePort, NodeRole},
    },
    utils::format_amount,
    validators::{self, SignerClient},
};

const VALIDATOR_DEPOSIT_IN_MILLIONS: u8 = 20;
const ZERO_ACCOUNT: &str = "0x0000000000000000000000000000000000000000";

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

    chain_nodes.retain(|node| node.role != NodeRole::Apps);

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

    chain_nodes.retain(|node| {
        node.role != NodeRole::Bootstrap
            && node.role != NodeRole::Apps
            && selected_machines.clone().contains(&node.name())
    });

    let _ = execute_install_or_upgrade(bootstrap_nodes, is_upgrade, max_parallel).await;
    let _ = execute_install_or_upgrade(chain_nodes.clone(), is_upgrade, max_parallel).await;

    if !is_upgrade {
        post_install(chain).await?;
    }

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
            (node, Ok(())) => successes.push(node),
            (node, Err(err)) => {
                println!("Node {} failed with error: {}", node.name(), err);
                failures.push(node.name());
            }
        }
    }

    for success in &successes {
        log::info!("SUCCESS: {}", success.name());
    }

    for failure in failures {
        log::error!("FAILURE: {failure}");
    }

    Ok(())
}

async fn post_install(chain: ChainInstance) -> Result<()> {
    if chain.chain()? == Chain::Zq2Testnet || chain.chain()? == Chain::Zq2Mainnet {
        log::info!("Skipping post install actions for chain: {}", chain.name());
        return anyhow::Ok(());
    }

    let genesis_private_key = chain.genesis_private_key()?;
    let url = chain.chain()?.get_api_endpoint()?;

    let genesis_address = EthereumAddress::from_private_key(&genesis_private_key)?;

    let client = SignerClient::new(&url, &genesis_private_key)?
        .get_signer()
        .await?;

    let gas_price = client.get_gas_price().await?;

    let mut start_nonce = client
        .get_transaction_count(genesis_address.address)
        .await?;

    for blessed_txns in BLESSED_TRANSACTIONS {
        if let Ok(Some(_)) = client
            .get_transaction_receipt(blessed_txns.hash.0.into())
            .await
        {
            continue;
        }

        let tx = TransactionRequest::default()
            .to(blessed_txns.sender)
            .nonce(start_nonce)
            .value(U256::from(blessed_txns.gas_limit as u128 * gas_price));

        start_nonce = start_nonce.add(1);

        let funding_txn = client.send_transaction(tx).await?;
        _ = funding_txn.get_receipt().await?;

        // Send blessed transaction itself
        let payload = Bytes::from(blessed_txns.payload.to_vec());
        _ = client.send_raw_transaction(&payload).await?;
    }

    anyhow::Ok(())
}

pub async fn get_config_file(config_file: &str, role: NodeRole, out: Option<&str>) -> Result<()> {
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
        if let Some(out) = out {
            std::fs::write(out, content)?;
            log::info!("Config file {out} successfully written");
        } else {
            println!("Config file for a node role {} in {}", role, chain.name());
            println!("---");
            println!("{content}");
            println!("---");
        }
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

    let genesis_private_key = chain.genesis_private_key()?;
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
    let private_keys = node.get_private_key()?;
    let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;
    let deposit_auth_signature = node_ethereum_address.secret_key.deposit_auth_signature(
        node.chain_id(),
        SecretKey::from_hex(genesis_private_key)?.to_evm_address(),
    );

    println!("Validator {}:", node.name());
    println!("z2 deposit --chain {} \\", node.chain()?);
    println!("\t--peer-id {} \\", node_ethereum_address.peer_id);
    println!("\t--public-key {} \\", node_ethereum_address.bls_public_key);
    println!("\t--deposit-auth-signature {deposit_auth_signature} \\");
    println!("\t--private-key {genesis_private_key} \\");
    println!("\t--reward-address {ZERO_ACCOUNT} \\");
    println!("\t--signing-address {ZERO_ACCOUNT} \\");
    println!("\t--amount {VALIDATOR_DEPOSIT_IN_MILLIONS}\n");

    Ok(())
}

pub async fn run_stakers(config_file: &str) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config.clone()).await?;
    let mut validators = chain.nodes().await?;
    validators.retain(|node| node.role == NodeRole::Bootstrap || node.role == NodeRole::Validator);

    println!("Retrieving the stakers info in the chain {}", chain.name());

    let genesis_private_key = chain.genesis_private_key()?;
    let signer_client =
        validators::SignerClient::new(&chain.chain()?.get_api_endpoint()?, &genesis_private_key)?;
    println!("Loading the stakers...");
    let stakers = signer_client.get_stakers().await?;

    println!("Loading the internal nodes...");
    let mut internal_validators = HashMap::<String, String>::new();
    for node in validators {
        let private_keys = node.get_private_key()?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;

        internal_validators.insert(
            node_ethereum_address.bls_public_key.to_string(),
            node.name(),
        );

        if !stakers.contains(&node_ethereum_address.bls_public_key)
            && node.role == NodeRole::Validator
        {
            log::warn!("{} is NOT a validator", node.name());
        }
    }

    for public_key in stakers {
        let stake = signer_client.get_stake(&public_key).await? as f64 / 10f64.powi(18);
        let future_stake =
            signer_client.get_future_stake(&public_key).await? as f64 / 10f64.powi(18);
        let public_key = &public_key.to_string();
        let name = internal_validators.get(public_key).unwrap_or(public_key);

        println!("---\n{}:", name.bold());

        println!(
            "\tStake        {:>width$} $ZIL",
            if stake != future_stake {
                format_amount(stake).red()
            } else {
                format_amount(stake).normal()
            },
            width = 30
        );

        if stake != future_stake {
            println!(
                "\tFuture stake {:>width$} $ZIL",
                format_amount(future_stake).green(),
                width = 30
            );
        }
    }

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
        let genesis_private_key = chain.genesis_private_key()?;
        let private_keys = node.get_private_key()?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;
        let deposit_auth_signature = node_ethereum_address.secret_key.deposit_auth_signature(
            node.chain_id(),
            SecretKey::from_hex(&genesis_private_key)?.to_evm_address(),
        );

        println!("{}", format!("Validator {}:", node.name()).yellow());

        let validator = validators::Validator::new(
            node_ethereum_address.peer_id,
            node_ethereum_address.bls_public_key,
            deposit_auth_signature,
        )?;
        let signer_client = validators::SignerClient::new(
            &chain.chain()?.get_api_endpoint()?,
            &genesis_private_key,
        )?;
        let deposit_params = validators::DepositParams::new(
            VALIDATOR_DEPOSIT_IN_MILLIONS,
            ZERO_ACCOUNT,
            ZERO_ACCOUNT,
        )?;

        let result = signer_client.deposit(&validator, &deposit_params).await;

        match result {
            Ok(()) => successes.push(node.name()),
            Err(err) => {
                println!("Node {} failed with error: {}", node.name(), err);
                failures.push(node.name());
            }
        }
    }

    for success in successes {
        log::info!("SUCCESS: {success}");
    }

    if !failures.is_empty() {
        for failure in failures {
            log::error!("FAILURE: {failure}");
        }
        log::error!(
            "Run `z2 deployer get-deposit-commands <chain_file>` to get the deposit command each node"
        );
    }

    Ok(())
}

pub async fn run_deposit_top_up(
    config_file: &str,
    node_selection: bool,
    amount: u64,
) -> Result<()> {
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
        "Running stake deposit top-up for the validators in the chain {}",
        chain.name()
    );

    let mut successes = vec![];
    let mut failures = vec![];

    for node in validators {
        let genesis_private_key = chain.genesis_private_key()?;
        let private_keys = node.get_private_key()?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;

        let signer_client = validators::SignerClient::new(
            &chain.chain()?.get_api_endpoint()?,
            &genesis_private_key,
        )?;

        println!("{}", format!("Validator {}:", node.name()).yellow());
        let result = signer_client
            .deposit_top_up(&node_ethereum_address.bls_public_key, amount)
            .await;

        match result {
            Ok(()) => successes.push(node.name()),
            Err(err) => {
                println!("Node {} failed with error: {}", node.name(), err);
                failures.push(node.name());
            }
        }
    }

    for success in successes {
        log::info!("SUCCESS: {success}");
    }

    if !failures.is_empty() {
        for failure in failures {
            log::error!("FAILURE: {failure}");
        }
    }

    Ok(())
}

pub async fn run_unstake(config_file: &str, node_selection: bool, amount: u64) -> Result<()> {
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
        "Running unstake for the validators in the chain {}",
        chain.name()
    );

    let mut successes = vec![];
    let mut failures = vec![];

    for node in validators {
        let genesis_private_key = chain.genesis_private_key()?;
        let private_keys = node.get_private_key()?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;

        let signer_client = validators::SignerClient::new(
            &chain.chain()?.get_api_endpoint()?,
            &genesis_private_key,
        )?;

        println!("{}", format!("Validator {}:", node.name()).yellow());
        let result = signer_client
            .unstake(&node_ethereum_address.bls_public_key, amount)
            .await;

        match result {
            Ok(()) => successes.push(node.name()),
            Err(err) => {
                println!("Node {} failed with error: {}", node.name(), err);
                failures.push(node.name());
            }
        }
    }

    for success in successes {
        log::info!("SUCCESS: {success}");
    }

    if !failures.is_empty() {
        for failure in failures {
            log::error!("FAILURE: {failure}");
        }
    }

    Ok(())
}

pub async fn run_withdraw(config_file: &str, node_selection: bool) -> Result<()> {
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
        "Running withdraw for the validators in the chain {}",
        chain.name()
    );

    let mut successes = vec![];
    let mut failures = vec![];

    for node in validators {
        let genesis_private_key = chain.genesis_private_key()?;
        let private_keys = node.get_private_key()?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;

        let signer_client = validators::SignerClient::new(
            &chain.chain()?.get_api_endpoint()?,
            &genesis_private_key,
        )?;

        println!("{}", format!("Validator {}:", node.name()).yellow());
        let result = signer_client
            .withdraw(&node_ethereum_address.bls_public_key, 0)
            .await;

        match result {
            Ok(()) => successes.push(node.name()),
            Err(err) => {
                println!("Node {} failed with error: {}", node.name(), err);
                failures.push(node.name());
            }
        }
    }

    for success in successes {
        log::info!("SUCCESS: {success}");
    }

    if !failures.is_empty() {
        for failure in failures {
            log::error!("FAILURE: {failure}");
        }
    }

    Ok(())
}

pub async fn run_rpc_call(
    method: &str,
    params: &Option<String>,
    config_file: &str,
    timeout: usize,
    node_selection: bool,
    port: NodePort,
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
        let current_port = port.to_owned();
        let current_method = method.to_owned();
        let current_params = params.to_owned();
        let permit = semaphore.clone().acquire_owned().await?;
        let machine_name = machine.name.clone();
        let remote_port = current_port.value();
        let future = task::spawn(async move {
            let local_port = machine.find_available_port().unwrap_or(6000);
            let tunnel = machine.open_tunnel(local_port, remote_port);
            if tunnel.is_none() {
                drop(permit);
                return (
                    machine,
                    Err(anyhow::anyhow!("Failed to open tunnel for {machine_name}",)),
                );
            }
            let mut tunnel = tunnel.unwrap();
            if !machine.wait_for_port(local_port, 20) {
                machine.close_tunnel(&mut tunnel);
                drop(permit);
                return (
                    machine,
                    Err(anyhow::anyhow!(
                        "Tunnel did not become ready for {machine_name}",
                    )),
                );
            }
            // Now call get_rpc_response, which will use curl to localhost:local_port
            let result = machine.get_rpc_response(
                &current_method,
                &current_params,
                timeout,
                local_port as u64,
            );
            machine.close_tunnel(&mut tunnel);
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

pub async fn run_ssh_command(
    command: Vec<String>,
    config_file: &str,
    node_selection: bool,
) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;

    // Create a list of chain instances
    let mut machines = chain.machines();
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

    println!("Running SSH command on {} nodes", chain.name());
    println!("🦆 Running the SSH command: '{}' .. ", command.join(" "));

    let column_width = target_nodes
        .iter()
        .map(|m| m.name.len())
        .max()
        .unwrap_or_default();

    for machine in target_nodes {
        let current_command = command.to_owned();
        let permit = semaphore.clone().acquire_owned().await?;
        let future = task::spawn(async move {
            let result = machine.run(&current_command.join(" "), false);
            drop(permit); // Release the permit when the task is done
            (machine, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    for result in results {
        match result? {
            (machine, Ok(output)) => {
                let output = if !output.status.success() {
                    format!(
                        "{}: {}",
                        "ERROR".red(),
                        std::str::from_utf8(&output.stderr)?.trim().to_owned().red()
                    )
                } else {
                    std::str::from_utf8(&output.stdout)?.trim().to_owned()
                };

                println!(
                    "---\n{:<width$}\n{}",
                    machine.name.bold(),
                    output,
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

pub async fn run_backup(config_file: &str, name: Option<String>, zip: bool) -> Result<()> {
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

    source_node.backup_to(name, zip).await
}

pub async fn run_restore(
    config_file: &str,
    max_parallel: usize,
    name: Option<String>,
    zip: bool,
    no_restart: bool,
) -> Result<()> {
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
        let name = name.clone();
        let permit = semaphore.clone().acquire_owned().await?;
        let mp = multi_progress.to_owned();
        let future = task::spawn(async move {
            let result = node.restore_from(name, zip, no_restart, &mp).await;
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
        log::error!("FAILURE: {failure}");
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
        log::error!("FAILURE: {failure}");
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
        log::error!("FAILURE: {failure}");
    }

    Ok(())
}

#[derive(Clone, Debug, Default, ValueEnum)]
pub enum Metrics {
    #[default]
    BlockNumber,
    ConsensusInfo,
}

pub async fn run_monitor(
    config_file: &str,
    metric: Metrics,
    node_selection: bool,
    follow: bool,
) -> Result<()> {
    let config = NetworkConfig::from_file(config_file).await?;
    let chain = ChainInstance::new(config).await?;
    let mut chain_nodes = chain.nodes().await?;
    chain_nodes.retain(|node| node.role != NodeRole::Apps);
    if matches!(metric, Metrics::ConsensusInfo) {
        chain_nodes
            .retain(|node| node.role == NodeRole::Bootstrap || node.role == NodeRole::Validator);
    }

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
        let metric = metric.to_owned();
        let permit = semaphore.clone().acquire_owned().await?;
        let mp = multi_progress.to_owned();
        let future = task::spawn(async move {
            let machine = node.machine.clone();
            let machine_name = machine.name.clone();
            let local_port = machine.find_available_port().unwrap_or(6000);
            let tunnel = machine.open_tunnel(local_port, NodePort::Admin.value());
            if tunnel.is_none() {
                drop(permit);
                return (
                    machine,
                    Err(anyhow::anyhow!("Failed to open tunnel for {machine_name}",)),
                );
            }
            let mut tunnel = tunnel.unwrap();
            if !machine.wait_for_port(local_port, 20) {
                machine.close_tunnel(&mut tunnel);
                drop(permit);
                return (
                    machine,
                    Err(anyhow::anyhow!(
                        "Tunnel did not become ready for {machine_name}",
                    )),
                );
            }
            let result = match metric {
                Metrics::BlockNumber => node.get_block_number(&mp, follow, local_port as u64).await,
                Metrics::ConsensusInfo => {
                    node.get_consensus_info(&mp, follow, local_port as u64)
                        .await
                }
            };
            machine.close_tunnel(&mut tunnel);
            drop(permit); // Release the permit when the task is done
            (machine, result)
        });
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;

    let mut failures = vec![];

    for result in results {
        if let (node, Err(err)) = result? {
            println!("Node {} failed with error: {}", node.name, err);
            failures.push(node.name);
        }
    }

    for failure in failures {
        log::error!("FAILURE: {failure}");
    }

    Ok(())
}
