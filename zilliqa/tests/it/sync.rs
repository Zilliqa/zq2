use ethers::{providers::Middleware, types::TransactionRequest};
use fs_extra::file::CopyOptions;
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
    network.run_until_block_finalized(5, 200).await.unwrap();
    wallet
        .send_transaction(TransactionRequest::pay(wallet.address(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    // wait 10 blocks for checkpoint to happen - then 3 more to finalize that block
    network.run_until_block_finalized(13, 200).await.unwrap();

    let checkpoint_path = network
        .nodes
        .first()
        .unwrap()
        .dir
        .as_ref()
        .unwrap()
        .path()
        .join(network.shard_id.to_string())
        .join("checkpoints")
        .join("10");

    // Create new node and pass it one of those checkpoint files
    let checkpoint_hash = wallet.get_block(10).await.unwrap().unwrap().hash.unwrap();
    let new_node_idx = network.add_node_with_options(NewNodeOptions {
        checkpoint: Some(Checkpoint {
            file: checkpoint_path.to_str().unwrap().to_string(),
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
    network.run_until_synced(new_node_idx).await;
    network.run_until_block_finalized(20, 200).await.unwrap();

    // check range of new node
    let base_height = *network
        .node_at(new_node_idx)
        .db
        .available_range()
        .unwrap()
        .start();
    assert_eq!(base_height, 3); // successful passive-sync to block 3.
}

#[zilliqa_macros::test(do_checkpoints)]
// default blocks_per_epoch = 10, epochs_per_checkpoint = 1
async fn state_sync(mut network: Network) {
    // Populate network with transactions
    let wallet = network.genesis_wallet().await;
    network.run_until_block_finalized(5, 200).await.unwrap();
    wallet
        .send_transaction(TransactionRequest::pay(wallet.address(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    network.run_until_block_finalized(13, 200).await.unwrap();

    // copy out checkpoint file; otherwise it will no longer exist after the restart
    let checkpoint_from = network
        .nodes
        .first()
        .unwrap()
        .dir
        .as_ref()
        .unwrap()
        .path()
        .join(network.shard_id.to_string())
        .join("checkpoints")
        .join("10");

    let checkpoint_path = tempfile::tempdir().unwrap();
    fs_extra::file::copy(
        checkpoint_from.as_path(),
        checkpoint_path.path().join("CKPT").as_path(),
        &CopyOptions::default(),
    )
    .unwrap();

    // pick a random node.
    let idx = network.random_index();
    assert_eq!(
        network
            .node_at(idx)
            .db
            .state_trie()
            .unwrap()
            .get_migrate_at()
            .unwrap(),
        u64::MAX // no state-sync
    );

    // Restart chosen node with checkpoint file
    let checkpoint_hash = wallet.get_block(10).await.unwrap().unwrap().hash.unwrap();
    network.restart_node_with_options(
        idx,
        NewNodeOptions {
            checkpoint: Some(Checkpoint {
                file: checkpoint_path
                    .path()
                    .join("CKPT")
                    .as_path()
                    .to_str()
                    .unwrap()
                    .to_string(),
                hash: Hash(checkpoint_hash.0),
            }),
            state_sync: Some(true),
            ..Default::default()
        },
        true,
    );

    assert_eq!(
        network
            .node_at(idx)
            .db
            .state_trie()
            .unwrap()
            .get_migrate_at()
            .unwrap(),
        10 // state-sync starts at the checkpoint block 10.
    );

    // run the network for a little bit
    // The test conditions only replay ONE block; and completes.
    network.run_until_block_finalized(20, 2000).await.unwrap();

    assert_eq!(
        network
            .node_at(idx)
            .db
            .state_trie()
            .unwrap()
            .get_migrate_at()
            .unwrap(),
        u64::MAX // state-sync complete
    );
}
