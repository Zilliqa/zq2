use ethers::{prelude::DeploymentTxFactory, providers::Middleware, types::TransactionRequest};
use primitive_types::{H160, H256};

use crate::{random_wallet, Network};

use super::deploy_contract;

#[tokio::test]
async fn get_storage_at() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getstorageat.
    let hash = deploy_contract!("contracts/Storage.sol", "Storage", wallet, network);

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();
    let contract_address = receipt.contract_address.unwrap();

    let value = provider
        .get_storage_at(contract_address, H256::zero(), None)
        .await
        .unwrap();
    assert_eq!(value, H256::from_low_u64_be(1234));

    // Calculate the storage position with keccak(LeftPad32(key, 0), LeftPad32(map position, 0))
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(receipt.from.as_bytes());
    bytes.extend_from_slice(&[0; 31]);
    bytes.push(1);
    let position = H256::from_slice(&ethers::utils::keccak256(bytes));
    let value = provider
        .get_storage_at(contract_address, position, None)
        .await
        .unwrap();
    assert_eq!(value, H256::from_low_u64_be(5678));
}

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
