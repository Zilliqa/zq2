use ethers::{providers::Middleware, types::TransactionRequest};
use primitive_types::H160;

use crate::{random_wallet, Network};

#[tokio::test]
async fn send_transaction() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    let to: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let tx = TransactionRequest::pay(to, 123);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    network
        .run_until_async(
            |p| async move { p.get_transaction_receipt(hash).await.unwrap().is_some() },
            10,
        )
        .await
        .unwrap();

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(receipt.to.unwrap(), to);
}
