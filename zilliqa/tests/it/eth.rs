use ethabi::ethereum_types::U64;
use std::fmt::Debug;

use ethers::{
    abi::FunctionExt,
    providers::{Middleware, Provider},
    types::{
        transaction::eip2718::TypedTransaction, BlockId, BlockNumber, Filter, TransactionRequest,
    },
    utils::keccak256,
};

use primitive_types::{H160, H256};
use serde::Serialize;

use crate::{deploy_contract, LocalRpcClient, Network};

#[zilliqa_macros::test]
async fn call_block_number(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/CallMe.sol",
        "CallMe",
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();

    let function = abi.function("currentBlock").unwrap();
    let call_tx = TransactionRequest::new()
        .to(receipt.contract_address.unwrap())
        .data(function.encode_input(&[]).unwrap());

    // Query the current block number with an `eth_call`.
    let response = wallet.call(&call_tx.clone().into(), None).await.unwrap();
    let block_number = function.decode_output(&response).unwrap()[0]
        .clone()
        .into_uint()
        .unwrap()
        .as_u64();

    // Verify it is correct.
    let expected_block_number = wallet.get_block_number().await.unwrap().as_u64();
    assert_eq!(block_number, expected_block_number);

    // Advance the network to the next block.
    network
        .run_until_async(
            |_| async { wallet.get_block_number().await.unwrap().as_u64() > block_number },
            50,
        )
        .await
        .unwrap();

    // Query the current block number with an `eth_call`.
    let response = wallet.call(&call_tx.clone().into(), None).await.unwrap();
    let new_block_number = function.decode_output(&response).unwrap()[0]
        .clone()
        .into_uint()
        .unwrap()
        .as_u64();

    // Verify it is correct.
    let expected_block_number = wallet.get_block_number().await.unwrap().as_u64();
    assert_eq!(new_block_number, expected_block_number);

    // Query the block number at the old block with an `eth_call`.
    let response = wallet
        .call(
            &call_tx.clone().into(),
            Some(BlockId::Number(BlockNumber::Number(block_number.into()))),
        )
        .await
        .unwrap();
    let old_block_number = function.decode_output(&response).unwrap()[0]
        .clone()
        .into_uint()
        .unwrap()
        .as_u64();

    // Verify it used the state from the old block.
    assert_eq!(old_block_number, block_number);
}

#[zilliqa_macros::test]
async fn get_block_transaction_count(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

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
    network
        .run_until_async(
            |_| async { wallet.get_block_number().await.unwrap().as_u64() > 1 },
            50,
        )
        .await
        .unwrap();

    // Send a transaction.
    let hash = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    network
        .run_until_async(
            |_| async {
                provider
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
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
    let count = count_by_number(provider, block_number - 1).await;
    assert_eq!(count, 0);

    // Check this block has a transaction count of one.
    let count = count_by_number(provider, block_number).await;
    assert_eq!(count, 1);
    let count = count_by_hash(provider, block_hash).await;
    assert_eq!(count, 1);

    // The latest block is the one with our transaction, because we stopped running the network after our receipt
    // appeared. So the latest block should also have a count of one.
    let count = count_by_number(provider, "latest").await;
    assert_eq!(count, 1);
}

#[zilliqa_macros::test]
async fn get_account_transaction_count(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    async fn count_at_block(provider: &Provider<LocalRpcClient>, params: (H160, U64)) -> u64 {
        provider
            .request::<_, U64>("eth_getTransactionCount", params)
            .await
            .unwrap()
            .as_u64()
    }

    network
        .run_until_async(
            |_| async { wallet.get_block_number().await.unwrap().as_u64() > 1 },
            50,
        )
        .await
        .unwrap();

    // Send a transaction.
    let hash = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    network
        .run_until_async(
            |_| async {
                provider
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();
    let block_number = receipt.block_number.unwrap();

    // Check the wallet has a transaction count of one.
    let count = count_at_block(provider, (wallet.address(), block_number)).await;
    assert_eq!(count, 1);

    // Check the wallet has a transaction count of zero at the previous block
    let count = count_at_block(provider, (wallet.address(), block_number - 1)).await;
    assert_eq!(count, 0);
}

#[zilliqa_macros::test]
async fn get_logs(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, contract) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();

    let emit_first = contract.function("emitEvents").unwrap();
    let call_tx = TransactionRequest::new()
        .to(contract_address)
        .data(emit_first.encode_input(&[]).unwrap());

    let call_tx_hash = wallet
        .send_transaction(call_tx, None)
        .await
        .unwrap()
        .tx_hash();
    // Wait until the transaction has succeeded.
    network
        .run_until_async(
            |_| async {
                wallet
                    .get_transaction_receipt(call_tx_hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    let receipt = wallet
        .get_transaction_receipt(call_tx_hash)
        .await
        .unwrap()
        .unwrap();

    // Make sure searching by both block hash and block number work.
    assert_eq!(
        wallet
            .get_logs(&Filter::new().at_block_hash(receipt.block_hash.unwrap()))
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        wallet
            .get_logs(&Filter::new().select(receipt.block_number.unwrap()))
            .await
            .unwrap()
            .len(),
        2
    );

    let base = Filter::new().at_block_hash(receipt.block_hash.unwrap());

    // Make sure filtering by address works.
    assert_eq!(
        wallet
            .get_logs(&base.clone().address(wallet.address()))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        wallet
            .get_logs(&base.clone().address(contract_address))
            .await
            .unwrap()
            .len(),
        2
    );

    // Make sure filtering by topic works.
    let transfer = contract.event("Transfer").unwrap().signature();
    let approval = contract.event("Approval").unwrap().signature();
    let nonsense = H256::from_low_u64_be(123);

    // Filter by topic0.
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic0(transfer))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic0(approval))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic0(nonsense))
            .await
            .unwrap()
            .len(),
        0
    );
    // Multiple topics in the same position act as an OR filter.
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic0(vec![transfer, approval]))
            .await
            .unwrap()
            .len(),
        2
    );
    // Including extra topics in the OR filter doesn't make a difference.
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic0(vec![transfer, approval, nonsense]))
            .await
            .unwrap()
            .len(),
        2
    );

    // Filter by topic1 (same value for both logs).
    let one = H256::from_low_u64_be(1);
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic1(one))
            .await
            .unwrap()
            .len(),
        2
    );

    // Filter by topic2 (different value for each log).
    let two = H256::from_low_u64_be(2);
    let three = H256::from_low_u64_be(3);
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic2(two))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic2(three))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic2(vec![two, three]))
            .await
            .unwrap()
            .len(),
        2
    );

    // Filter by multiple topics.
    assert_eq!(
        wallet
            .get_logs(
                &base
                    .clone()
                    .topic0(vec![transfer, approval])
                    .topic1(one)
                    .topic2(vec![two, three])
            )
            .await
            .unwrap()
            .len(),
        2
    );
}

#[zilliqa_macros::test]
async fn get_storage_at(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getstorageat.
    let (hash, abi) = deploy_contract(
        "tests/it/contracts/Storage.sol",
        "Storage",
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();

    let value = wallet
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
    let value = wallet
        .get_storage_at(contract_address, position, None)
        .await
        .unwrap();
    assert_eq!(value, H256::from_low_u64_be(5678));

    // Save the current block number
    let old_block_number = wallet.get_block_number().await.unwrap().as_u64();

    // Modify the contract state.
    let function = abi.function("update").unwrap();
    let update_tx = TransactionRequest::new()
        .to(receipt.contract_address.unwrap())
        .data(function.encode_input(&[]).unwrap());
    let update_tx_hash = wallet
        .send_transaction(update_tx, None)
        .await
        .unwrap()
        .tx_hash();
    // Advance the network to the next block.
    network
        .run_until_async(
            |_| async {
                wallet
                    .get_transaction_receipt(update_tx_hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // verify the new state
    let value = wallet
        .get_storage_at(contract_address, H256::zero(), None)
        .await
        .unwrap();
    assert_eq!(value, H256::from_low_u64_be(9876));

    // verify that the state at the old block can still be fetched correctly
    let value = wallet
        .get_storage_at(
            contract_address,
            H256::zero(),
            Some(BlockId::Number(BlockNumber::Number(
                old_block_number.into(),
            ))),
        )
        .await
        .unwrap();
    assert_eq!(value, H256::from_low_u64_be(1234));
}

#[zilliqa_macros::test]
async fn send_transaction(mut network: Network) {
    let wallet = network.genesis_wallet().await;

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
            |_| async {
                wallet
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();

    assert_eq!(receipt.to.unwrap(), to);
    assert_eq!(receipt.from, wallet.address());
}

#[zilliqa_macros::test]
async fn eth_call(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/SetGetContractValue.sol",
        "SetGetContractValue",
        &wallet,
        &mut network,
    )
    .await;

    network
        .run_until_async(
            |_| async {
                wallet
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    let getter = abi.function("getInt256").unwrap();

    let receipt = wallet.get_transaction_receipt(hash).await;

    assert!(receipt.is_ok());
    let receipt = receipt.unwrap().unwrap();

    let contract_address = receipt.contract_address.unwrap();

    let mut tx = TransactionRequest::new();
    tx.to = Some(contract_address.into());
    tx.data = Some(getter.selector().into());

    let value = wallet.call(&tx.into(), None).await.unwrap();

    assert_eq!(H256::from_slice(value.as_ref()), H256::from_low_u64_be(99));
}
