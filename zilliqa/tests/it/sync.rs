use std::fs;

use ethers::{providers::Middleware, types::TransactionRequest};
use tracing::info;
use zilliqa::{cfg::Checkpoint, crypto::Hash};

use crate::{Network, NewNodeOptions};

// Test a pruning node does not hold old blocks.
#[zilliqa_macros::test]
async fn prune_interval(mut network: Network) {
    network.run_until_block_finalized(5, 100).await.unwrap();

    info!("Adding pruned node.");
    let index = network.add_node_with_options(crate::NewNodeOptions {
        prune_interval: Some(20),
        ..Default::default()
    });
    network.run_until_synced(index).await;

    network.run_until_block_finalized(25, 1000).await.unwrap();

    let range = network.node_at(index).db.available_range().unwrap();
    info!("Pruned range: {range:?}");
    assert_eq!(range.count(), 20);
}

#[zilliqa_macros::test(do_checkpoints)]
async fn base_height(mut network: Network) {
    // Populate network with transactions
    let wallet = network.genesis_wallet().await;
    // Run until block 9 so that we can insert a tx in block 10 (note that this transaction may not *always* appear in the desired block, therefore we do not assert its presence later)
    network.run_until_block(&wallet, 9.into(), 200).await;

    let _hash = wallet
        .send_transaction(TransactionRequest::pay(wallet.address(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    // wait 10 blocks for checkpoint to happen - then 3 more to finalize that block
    network.run_until_block(&wallet, 13.into(), 200).await;

    let checkpoint_files = network
        .nodes
        .iter()
        .map(|node| {
            node.dir
                .as_ref()
                .unwrap()
                .path()
                .join(network.shard_id.to_string())
                .join("checkpoints")
                .join("10")
        })
        .collect::<Vec<_>>();

    let mut len_check = 0;
    for path in &checkpoint_files {
        let metadata = fs::metadata(path).unwrap();
        assert!(metadata.is_file());
        let file_len = metadata.len();
        assert!(file_len != 0);
        assert!(len_check == 0 || len_check == file_len); // len_check = 0 on first loop iteration
        len_check = file_len;
    }

    // Add a non-validator node, since passive-sync does not work otherwise
    let non_validator_idx = network.add_node();

    // Create new node and pass it one of those checkpoint files
    let checkpoint_path = checkpoint_files[0].to_str().unwrap().to_owned();
    let checkpoint_hash = wallet.get_block(10).await.unwrap().unwrap().hash.unwrap();
    let new_node_idx = network.add_node_with_options(NewNodeOptions {
        checkpoint: Some(Checkpoint {
            file: checkpoint_path,
            hash: Hash(checkpoint_hash.0),
        }),
        base_height: Some(3),
        ..Default::default()
    });

    // Confirm wallet and new_node_wallet have the same block and state
    let new_node_wallet = network.wallet_of_node(new_node_idx).await;
    let latest_block_number = new_node_wallet.get_block_number().await.unwrap();
    assert_eq!(latest_block_number, 10.into());

    // check the new node catches up and keeps up with block production
    network.run_until_synced(non_validator_idx).await;
    network.run_until_synced(new_node_idx).await;
    network
        .run_until_block(&new_node_wallet, 20.into(), 200)
        .await;

    // check range of new wallet
    let base_height = *network
        .node_at(new_node_idx)
        .db
        .available_range()
        .unwrap()
        .start();
    assert_eq!(base_height, 3);
}
