use crate::setup;
//use alloy::core::primitives::{Address, B256, U256};
use alloy::core::primitives::U256;
use alloy::network::TransactionBuilder;
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use anyhow::{Result, anyhow};
use std::ops::Add;
use tokio::process::Command;
use zilliqa::exec::BLESSED_TRANSACTIONS;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IVALIDATOR_MANAGER,
    "abi/IValidatorManager.json"
);

/// Dispatches the blessed transactions to a chain
pub async fn init_chain(setup: &setup::Setup) -> Result<()> {
    let provider = setup.get_provider().await?;
    let signer = setup.get_signer().await?;
    let gas_price = provider.get_gas_price().await?;
    let from_address = signer.address();
    let mut cur_nonce = provider.get_transaction_count(from_address).await?;
    let mut idx = 0;
    println!("gas_price {gas_price} address {from_address:x} txn_count {cur_nonce}");
    for blessed in BLESSED_TRANSACTIONS {
        idx += 1;
        println!("[{idx}/{}]", BLESSED_TRANSACTIONS.len());
        if let Ok(Some(_)) = provider.get_transaction_receipt(blessed.hash.into()).await {
            // Already did this one.
            continue;
        }
        let tx = TransactionRequest::default()
            .to(blessed.sender)
            .nonce(cur_nonce)
            .value(U256::from(blessed.gas_limit) * U256::from(gas_price))
            .with_gas_price(gas_price);
        cur_nonce = cur_nonce.add(1);
        let funding_txn = provider.send_transaction(tx).await?;
        _ = funding_txn.watch().await?;
        _ = provider
            .send_raw_transaction(&blessed.payload)
            .await?
            .watch()
            .await?;
    }
    // Check if the UCCB base contracts are already deployed.
    let uccb_data = setup.get_uccb_data()?;
    println!(
        " validator_manager = {:x} , chain_gateway = {:x}",
        uccb_data.validator_manager_address, uccb_data.chain_gateway_address
    );
    let vm_deployed = !provider
        .get_code_at(uccb_data.validator_manager_address)
        .await?
        .is_empty();
    let cg_deployed = !provider
        .get_code_at(uccb_data.chain_gateway_address)
        .await?
        .is_empty();
    match (vm_deployed, cg_deployed) {
        (false, false) => {
            println!("Deploying UCCB contracts .. ");
            // We initially deploy with no validators, and add them later.
            let mut script_cmd = Command::new("forge");
            let uccb_deployer_script = format!(
                "{}/zq2/zilliqa/src/contracts/scripts/deploy_uccb.s.sol",
                setup.base_dir
            );
            println!(
                "P = 0x{:x} S = 0x{:x} X = {uccb_deployer_script}",
                uccb_data.private_key, uccb_data.salt
            );
            script_cmd.env(
                "PRIVATE_KEY_OWNER",
                format!("0x{:x}", uccb_data.private_key),
            );
            script_cmd.env("SALT", format!("0x{:x}", uccb_data.salt));
            // So as not to disturb the deployment address.
            script_cmd.env("VALIDATORS", "");
            script_cmd.args(vec![
                "script",
                &uccb_deployer_script,
                "--fork-url",
                &setup.get_json_rpc_url(true),
                "--legacy",
                "--broadcast",
            ]);
            let mut running = script_cmd.spawn()?;
            if !running.wait().await?.success() {
                return Err(anyhow!("Couldn't install UCCB - {running:?}"));
            }
        }
        (true, true) => println!("UCCB contracts already deployed"),
        (_, _) => {
            return Err(anyhow!(
                "UCCB contracts partially deployed - please run creation manually"
            ));
        }
    }
    // Populate the validator manager contract.
    let validator_manager = IVALIDATOR_MANAGER::new(uccb_data.validator_manager_address, &provider);
    let first = setup
        .config
        .shape
        .nodes
        .iter()
        .next()
        .ok_or(anyhow!("Couldn't find the first node in the network"))?
        .0;
    println!(" .. Adding node {first} to validator manager .. ");
    let data = setup
        .config
        .node_data
        .get(first)
        .ok_or(anyhow!("Node {first} does not have a description"))?;
    let txn = validator_manager
        .addValidator(data.address)
        .gas_price(gas_price)
        .send()
        .await?;
    _ = txn.watch().await?;
    Ok(())
}
