use std::{sync::Arc, time::Duration};

use anyhow::Result;
use tokio::time::sleep;
use tracing::info;

use crate::{
    db::Db,
    time::SystemTime,
    transaction::Log::{Evm, Scilla},
};

// The following procedure iterates over all blocks and their transactions starting
// from last view down to genesis and insert into db: sender, optionally recipient and all
// addresses emitted in the receipt logs for given transaction hash.
pub fn check_and_build_ots_indices(db: Arc<Db>, last_view: u64) -> Result<()> {
    let table_key = "ots_indices_rebuilt";

    let last_view = match db.get_value_from_aux_table(table_key)? {
        Some(bytes) => {
            let arr: [u8; 8] = match bytes.as_slice().try_into() {
                Ok(arr) => arr,
                // Previous non-integer marker stored in db
                Err(_) => return Ok(()),
            };
            u64::from_le_bytes(arr)
        }
        None => last_view,
    };

    if last_view == 0 {
        return Ok(());
    }

    tokio::spawn(async move {
        let now = SystemTime::now();

        for view in (0..=last_view).rev() {
            let Ok(Some(block)) = db.get_block_by_view(view) else {
                continue;
            };

            for txn_hash in block.transactions {
                let mut addresses = Vec::with_capacity(64);

                let Ok(Some(txn)) = db.get_transaction(&txn_hash) else {
                    continue;
                };

                addresses.push(txn.signer);

                let txn = txn.tx.into_transaction();
                if let Some(dest) = txn.to_addr() {
                    addresses.push(dest);
                }

                let Ok(block_receipts) = db.get_transaction_receipts_in_block(&block.header.hash)
                else {
                    continue;
                };

                let Some(receipt) = block_receipts
                    .iter()
                    .find(|receipt| receipt.tx_hash == txn_hash)
                else {
                    continue;
                };

                for log in &receipt.logs {
                    match log {
                        Evm(log) => {
                            addresses.push(log.address);
                        }
                        Scilla(log) => {
                            addresses.push(log.address);
                        }
                    }
                }

                for address in addresses {
                    let _ = db.add_touched_address(address, txn_hash);
                }
                // Give some breath to db before proceeding with next transaction
                sleep(Duration::from_millis(5)).await;
            }
            let _ = db.insert_value_to_aux_table(table_key, view.to_le_bytes().to_vec());

            if view % 100_000 == 0 {
                info!("Ots indices built down to block: {:?}", view);
            }
        }
        info!("Migration took: {:?}", now.elapsed());
    });

    Ok(())
}
