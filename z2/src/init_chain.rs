use crate::{setup, utils};
use anyhow::{Result, anyhow};
use ethers::{
    middleware::Middleware,
    prelude::{Bytes, TransactionRequest},
    types::{H160, H256, U256},
};
use std::ops::Add;
use tokio::process::Command;
use zilliqa::exec::BLESSED_TRANSACTIONS;

/// Dispatches the blessed transactions to a chain
pub async fn init_chain(setup: &setup::Setup) -> Result<()> {
    let signer = setup.get_signer().await?;
    let gas_price = signer.get_gas_price().await?;
    let from_address = signer.address();
    let mut cur_nonce = signer.get_transaction_count(from_address, None).await?;
    let mut idx = 0;
    println!("gas_price {gas_price} address {from_address:x} txn_count {cur_nonce}");
    for blessed in BLESSED_TRANSACTIONS {
        idx += 1;
        println!("[{idx}/{}]", BLESSED_TRANSACTIONS.len());
        if let Ok(Some(_)) = signer.get_transaction_receipt(H256(blessed.hash.0)).await {
            // Already did this one.
            continue;
        }
        let tx = TransactionRequest::new()
            .to(H160(blessed.sender.0.into()))
            .nonce(cur_nonce)
            .value(U256::from(blessed.gas_limit) * gas_price);
        cur_nonce = cur_nonce.add(1);
        let funding_txn = signer.send_transaction(tx, None).await?;
        _ = funding_txn.await?;
        let payload = Bytes::from(blessed.payload.to_vec());
        _ = signer.send_raw_transaction(payload).await?;
    }
    // Check if the UCCB base contracts are already deployed.
    let uccb_data = setup.get_uccb_data()?;
    let vm_deployed = signer
        .get_code(
            utils::ethers_from_alloy(&uccb_data.validator_manager_address)?,
            None,
        )
        .await
        .is_ok();
    let cg_deployed = signer
        .get_code(
            utils::ethers_from_alloy(&uccb_data.chain_gateway_address)?,
            None,
        )
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
    Ok(())
}
