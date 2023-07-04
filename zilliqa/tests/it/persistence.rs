use crate::{Network, TestNode};
use ethers::providers::Middleware;
use ethers::types::TransactionRequest;
use primitive_types::H160;
use zilliqa::crypto::Hash;
use zilliqa::crypto::SecretKey;

#[zilliqa_macros::test]
async fn block_and_tx_data_persistence(mut network: Network<'_>) {
    let wallet = network.random_wallet();
    // send and include tx
    let hash = Hash(
        wallet
            .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
            .await
            .unwrap()
            .tx_hash()
            .0,
    );

    network
        .run_until(
            |n| n.node().get_transaction_receipt(hash).unwrap().is_some(),
            50,
        )
        .await
        .unwrap();

    // make one block without txs
    network
        .run_until(
            |n| n.node().get_latest_block().unwrap().map_or(0, |b| b.view()) >= 2,
            50,
        )
        .await
        .unwrap();

    let node = network.remove_node();

    let inner = node.inner.lock().unwrap();
    let last_view = inner.view() - 1;
    let receipt = inner.get_transaction_receipt(hash).unwrap().unwrap();
    let finalized_view = inner.get_finalized_height().unwrap();
    let block_with_tx = inner
        .get_block_by_hash(receipt.block_hash)
        .unwrap()
        .unwrap();
    let last_block = inner.get_block_by_view(last_view).unwrap().unwrap();
    let tx = inner.get_transaction_by_hash(hash).unwrap().unwrap();
    // sanity check
    assert_eq!(tx.hash(), hash);
    assert_eq!(block_with_tx.transactions.len(), 1);

    // drop and re-create the node using the same datadir:
    drop(inner);
    #[allow(clippy::redundant_closure_call)]
    let dir = (|node: TestNode| node.dir)(node); // move dir out and drop the rest of node
    let (newnode, _) = crate::node(SecretKey::new().unwrap(), 0, dir);

    let inner = newnode.inner.lock().unwrap();

    // finalized height was saved
    assert_eq!(inner.get_finalized_height().unwrap(), finalized_view);

    // all blocks created were saved up till the last one
    let loaded_last_block = inner.get_block_by_view(last_view).unwrap();
    assert!(loaded_last_block.is_some());
    assert_eq!(loaded_last_block.unwrap().hash(), last_block.hash());

    // tx was saved, including its receipt
    let loaded_tx_block = inner
        .get_block_by_view(block_with_tx.view())
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
            .transaction
            .payload,
        tx.transaction.payload
    );
}
