use ethabi::ethereum_types::U64;
use ethers::abi::FunctionExt;
use ethers::solc::EvmVersion;
use ethers::{
    prelude::{CompilerInput, DeploymentTxFactory},
    providers::{Middleware, Provider},
    types::{transaction::eip2718::TypedTransaction, TransactionRequest},
    utils::keccak256,
};
use std::fmt::Debug;

use primitive_types::{H160, H256};
use serde::Serialize;

use crate::{random_wallet, LocalRpcClient, Network};

use super::deploy_contract;

#[tokio::test]
async fn get_block_transaction_count() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    async fn count_by_number<T: Debug + Serialize + Send + Sync>(
        provider: &Provider<LocalRpcClient>,
        number: T,
    ) -> u64 {
        provider
            .request::<_, U64>("eth_getBlockTransactionCountByNumber", [number])
            .await
            .unwrap()
            .as_u64()
    }

    async fn count_by_hash(provider: &Provider<LocalRpcClient>, hash: H256) -> u64 {
        provider
            .request::<_, U64>("eth_getBlockTransactionCountByHash", [hash])
            .await
            .unwrap()
            .as_u64()
    }

    // Send a transaction.
    let hash = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

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
    let block_hash = receipt.block_hash.unwrap();
    let block_number = receipt.block_number.unwrap();

    // Check the previous block has a transaction count of zero.
    let count = count_by_number(&provider, block_number - 1).await;
    assert_eq!(count, 0);

    // Check this block has a transaction count of one.
    let count = count_by_number(&provider, block_number).await;
    assert_eq!(count, 1);
    let count = count_by_hash(&provider, block_hash).await;
    assert_eq!(count, 1);

    // The latest block is the one with our transaction, because we stopped running the network after our receipt
    // appeared. So the latest block should also have a count of one.
    let count = count_by_number(&provider, "latest").await;
    assert_eq!(count, 1);
}

#[tokio::test]
async fn get_storage_at() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getstorageat.
    let (hash, _) = deploy_contract!("contracts/Storage.sol", "Storage", wallet, network);

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

    // Transform the transaction to its final form, so we can caculate the expected hash.
    let mut tx: TypedTransaction = tx.into();
    wallet.fill_transaction(&mut tx, None).await.unwrap();
    let sig = wallet.signer().sign_transaction_sync(&tx).unwrap();
    let expected_hash = H256::from_slice(&keccak256(tx.rlp_signed(&sig)));

    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    assert_eq!(hash, expected_hash);

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

#[tokio::test]
async fn eth_call() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    let (hash, abi) = deploy_contract!(
        "contracts/SimpleContract.sol",
        "SimpleContract",
        wallet,
        network
    );

    let getter = abi.function("getInt256").unwrap();

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();
    let contract_address = receipt.contract_address.unwrap();

    let mut tx = TransactionRequest::new();
    tx.to = Some(contract_address.into());
    tx.data = Some(getter.selector().into());

    let value = provider.call(&tx.into(), None).await.unwrap();

    assert_eq!(H256::from_slice(value.as_ref()), H256::from_low_u64_be(99));
}
