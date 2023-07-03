use crate::Network;
use ethers::providers::Middleware;
use ethers::types::TransactionRequest;
use primitive_types::H160;
use zilliqa::crypto::Hash;

#[zilliqa_macros::test]
async fn block_and_tx_data_persistence(mut network: Network<'_>) {
    let wallet = network.random_wallet();
    // make one block
    network
        .run_until(
            |n| n.node().get_latest_block().unwrap().map_or(0, |b| b.view()) >= 1,
            50,
        )
        .await
        .unwrap();

    let hash = Hash(
        wallet
            .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
            .await
            .unwrap()
            .tx_hash()
            .0,
    );

    // make two more blocks
    network
        .run_until(
            |n| n.node().get_latest_block().unwrap().map_or(0, |b| b.view()) >= 3,
            50,
        )
        .await
        .unwrap();

    let node = network.remove_node();
    let inner = node.inner.lock().unwrap();
    let view = inner.view();
    let finalized_view = inner.get_finalized_height().unwrap();
    let block2 = inner.get_block_by_view(2).unwrap().unwrap();
    let receipt = inner.get_transaction_receipt(hash).unwrap().unwrap();
    let tx = inner.get_transaction_by_hash(hash).unwrap().unwrap();
    // sanity check
    assert!(view >= 3);
    assert!(finalized_view >= 1);
    assert_eq!(block2.transactions.len(), 1);
    assert_eq!(receipt.block_hash, block2.hash());
}
