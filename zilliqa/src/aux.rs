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
            let Ok(Some(brt)) =
                db.get_block_and_receipts_and_transactions(crate::db::BlockFilter::View(view))
            else {
                continue;
            };

            for txn in brt.transactions {
                let mut addresses = Vec::with_capacity(64);

                addresses.push(txn.signer);

                if let Some(dest) = txn.tx.into_transaction().to_addr() {
                    addresses.push(dest);
                }

                let Some(receipt) = brt
                    .receipts
                    .iter()
                    .find(|receipt| receipt.tx_hash == txn.hash)
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
                    let _ = db.add_touched_address(address, txn.hash);
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
