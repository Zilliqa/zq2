use crate::setup;
//use alloy::core::primitives::{Address, B256, U256};
use alloy::core::primitives::U256;
use alloy::network::TransactionBuilder;
use alloy::rpc::types::TransactionRequest;
use anyhow::{Result, anyhow};
use std::ops::Add;
use tokio::process::Command;
use zilliqa::exec::BLESSED_TRANSACTIONS;

/// Dispatches the blessed transactions to a chain
pub async fn init_chain(setup: &setup::Setup) -> Result<()> {
    let inter = setup.get_interactor().await?;
    let gas_price = inter.provider.get_gas_price().await?;
    let from_address = inter.signer.address();
    let mut cur_nonce = inter.provider.get_transaction_count(from_address).await?;
    let mut idx = 0;
    println!("gas_price {gas_price} address {from_address:x} txn_count {cur_nonce}");
    for blessed in BLESSED_TRANSACTIONS {
        idx += 1;
        println!("[{idx}/{}]", BLESSED_TRANSACTIONS.len());
        if let Ok(Some(_)) = inter
            .provider
            .get_transaction_receipt(blessed.hash.into())
            .await
        {
            // Already did this one.
            continue;
        }
        let tx = TransactionRequest::default()
            .to(blessed.sender)
            .nonce(cur_nonce)
            .value(U256::from(blessed.gas_limit) * U256::from(gas_price))
            .with_gas_price(gas_price);
        cur_nonce = cur_nonce.add(1);
        let funding_txn = inter.provider.send_transaction(tx).await?;
        _ = funding_txn.watch().await?;
        _ = inter
            .provider
            .send_raw_transaction(&blessed.payload)
            .await?
            .watch()
            .await?;
    }
    // Check if the UCCB base contracts are already deployed.
    let uccb_data = setup.get_uccb_data()?;
    let vm_deployed = inter
        .provider
        .get_code_at(uccb_data.validator_manager_address)
        .await
        .is_ok();
    let cg_deployed = inter
        .provider
        .get_code_at(uccb_data.chain_gateway_address)
        .await
        .is_ok();
    match (vm_deployed, cg_deployed) {
        (true, true) => {
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
        (false, false) => println!("UCCB contracts already deployed"),
        (_, _) => {
            return Err(anyhow!(
                "UCCB contracts partially deployed - please run creation manually"
            ));
        }
    }
    // Populate the validator manager contract.

    Ok(())
}
