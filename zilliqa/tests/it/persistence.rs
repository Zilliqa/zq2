use ethers::{providers::Middleware, types::TransactionRequest};
use primitive_types::H160;
use tracing::*;
use zilliqa::crypto::{Hash, SecretKey};

use crate::{ConsensusConfig, Network, NodeConfig, TestNode};

#[zilliqa_macros::test]
async fn block_and_tx_data_persistence(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    // send and include tx
    let hash = Hash(
        wallet
            .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
            .await
            .unwrap()
            .tx_hash()
            .0,
    );

    let index = network.random_index();

    network
        .run_until(
            |n| {
                n.get_node(index)
                    .get_transaction_receipt(hash)
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // make one block without txs
    network
        .run_until(
            |n| {
                let block = n
                    .get_node(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.number());
                block >= 3
            },
            50,
        )
        .await
        .unwrap();

    let node = network.remove_node(index);

    let inner = node.inner.lock().unwrap();
    let last_number = inner.number() - 1;
    let receipt = inner.get_transaction_receipt(hash).unwrap().unwrap();
    let _finalized_number = inner.get_finalized_height();
    let block_with_tx = inner
        .get_block_by_hash(receipt.block_hash)
        .unwrap()
        .unwrap();
    let last_block = inner.get_block_by_number(last_number).unwrap().unwrap();
    let tx = inner.get_transaction_by_hash(hash).unwrap().unwrap();
    // sanity check
    assert_eq!(tx.hash, hash);
    assert_eq!(block_with_tx.transactions.len(), 1);

    // drop and re-create the node using the same datadir:
    drop(inner);
    #[allow(clippy::redundant_closure_call)]
    let dir = (|mut node: TestNode| node.dir.take())(node).unwrap(); // move dir out and drop the rest of node
    let config = NodeConfig {
        consensus: ConsensusConfig {
            genesis_committee: network.genesis_committee,
            genesis_hash: None,
            is_main: true,
            genesis_accounts: Network::genesis_accounts(&network.genesis_key),
            ..Default::default()
        },
        ..Default::default()
    };
    let result = crate::node(config, SecretKey::new().unwrap(), 0, Some(dir));

    // Sometimes, the dropping Arc<Node> (by dropping the TestNode above) does not actually drop
    // the underlying Node. See: https://github.com/Zilliqa/zq2/issues/299
    // As this is very painful to debug, should only ever be relevant for tests like these, and CI
    // should run enough samples to still have decent test coverage, we simply skip the rest of the
    // test if this happens.
    let Ok((newnode, _, _)) = result else {
        warn!(
            "Failed to release database lock. Skipping test, with seed {}.",
            network.seed
        );
        return;
    };
    let inner = newnode.inner.lock().unwrap();

    // ensure all blocks created were saved up till the last one
    let loaded_last_block = inner.get_block_by_number(last_number).unwrap();
    assert!(loaded_last_block.is_some());
    assert_eq!(loaded_last_block.unwrap().hash(), last_block.hash());

    // ensure tx was saved, including its receipt
    let loaded_tx_block = inner
        .get_block_by_number(block_with_tx.number())
        .unwrap()
        .unwrap();
    assert_eq!(loaded_tx_block.hash(), block_with_tx.hash());
    assert_eq!(loaded_tx_block.transactions.len(), 1);
    assert!(inner.get_transaction_receipt(hash).unwrap().is_some());
    assert_eq!(
        inner
            .get_transaction_by_hash(hash)
            .unwrap()
            .unwrap()
            .tx
            .into_transaction()
            .payload(),
        tx.tx.into_transaction().payload()
    );
}
