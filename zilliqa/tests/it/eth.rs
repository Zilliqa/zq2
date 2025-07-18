use std::{fmt::Debug, ops::DerefMut};

use alloy::primitives::{Address, hex};
use ethabi::{Token, ethereum_types::U64};
use ethers::{
    abi::FunctionExt,
    core::types::{Bytes, Signature},
    providers::{Middleware, MiddlewareError, Provider},
    types::{
        BlockId, BlockNumber, Eip1559TransactionRequest, Eip2930TransactionRequest, Filter,
        Transaction, TransactionReceipt, TransactionRequest,
        transaction::{
            eip2718::TypedTransaction,
            eip2930::{AccessList, AccessListItem},
        },
    },
    utils::keccak256,
};
use futures::{StreamExt, future::join_all};
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{LocalRpcClient, Network, Wallet, deploy_contract};

#[zilliqa_macros::test]
async fn call_block_number(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/CallMe.sol",
        "CallMe",
        0u128,
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
            || async { wallet.get_block_number().await.unwrap().as_u64() > block_number },
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
            || async { wallet.get_block_number().await.unwrap().as_u64() > 1 },
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
            || async {
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
async fn get_transaction_count_pending(mut network: Network) {
    let wallet_1 = network.genesis_wallet().await;
    let wallet_2 = network.random_wallet().await;

    let provider = wallet_1.provider();

    async fn get_count<T: Debug + Serialize + Send + Sync>(
        address: H160,
        provider: &Provider<LocalRpcClient>,
        number: T,
    ) -> u64 {
        provider
            .request::<_, U64>("eth_getTransactionCount", (address, number))
            .await
            .unwrap()
            .as_u64()
    }

    // Both wallets should have no transactions pending.
    let count = get_count(wallet_1.address(), provider, "pending").await;
    assert_eq!(count, 0);
    let count = get_count(wallet_2.address(), provider, "pending").await;
    assert_eq!(count, 0);

    // Send a transaction from wallet 1 to wallet 2.
    let _hash_1 = wallet_1
        .send_transaction(
            TransactionRequest::pay(wallet_2.address(), 10).nonce(0),
            None,
        )
        .await
        .unwrap()
        .tx_hash();

    // Wallet 1 should now have 1 transaction pending, and no transactions in the latest block.
    let count = get_count(wallet_1.address(), provider, "pending").await;
    assert_eq!(count, 1);
    let count = get_count(wallet_1.address(), provider, "latest").await;
    assert_eq!(count, 0);

    // Send a transaction from wallet 1 to wallet 2.
    let hash_2 = wallet_1
        .send_transaction(
            TransactionRequest::pay(wallet_2.address(), 10).nonce(1),
            None,
        )
        .await
        .unwrap()
        .tx_hash();

    // Wallet 1 should now have 2 transactions pending, and still no transactions in the latest block.
    let count = get_count(wallet_1.address(), provider, "pending").await;
    assert_eq!(count, 2);
    let count = get_count(wallet_1.address(), provider, "latest").await;
    assert_eq!(count, 0);

    // Ensure transaction count is account specific.
    let count = get_count(wallet_2.address(), provider, "pending").await;
    assert_eq!(count, 0);

    // Process pending transaction
    network
        .run_until_async(
            || async {
                provider
                    .get_transaction_receipt(hash_2)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // Wallet 1 should no longer have any pending transactions, and should have 2 transactions in the
    // latest block, leading to 2 returned for both "pending" and "latest".
    let count = get_count(wallet_1.address(), provider, "pending").await;
    assert_eq!(count, 2);
    let count = get_count(wallet_1.address(), provider, "latest").await;
    assert_eq!(count, 2);

    // Send a transaction from wallet 1 to wallet 2.
    wallet_1
        .send_transaction(
            TransactionRequest::pay(wallet_2.address(), 10).nonce(3),
            None,
        )
        .await
        .unwrap();

    // Wallet 1 should no longer have any pending transactions, and should have 2 transactions in the
    // latest block, leading to 2 returned for both "pending" and "latest".
    let count = get_count(wallet_1.address(), provider, "pending").await;
    assert_eq!(count, 2);

    // Send a transaction from wallet 1 to wallet 2.
    wallet_1
        .send_transaction(
            TransactionRequest::pay(wallet_2.address(), 10).nonce(2),
            None,
        )
        .await
        .unwrap();

    // Wallet 1 should no longer have any pending transactions, and should have 2 transactions in the
    // latest block, leading to 2 returned for both "pending" and "latest".
    let count = get_count(wallet_1.address(), provider, "pending").await;
    assert_eq!(count, 4);
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
            || async { wallet.get_block_number().await.unwrap().as_u64() > 1 },
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
            || async {
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
async fn eth_get_transaction_receipt(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Deploy a contract to generate a transaction receipt
    let (hash, _abi) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    // Wait for the transaction to be mined
    network
        .run_until_async(
            || async {
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

    // Get the transaction receipt
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();

    dbg!(&receipt);

    // Verify the transaction receipt fields
    assert_eq!(receipt.transaction_hash, hash);
    assert!(receipt.block_hash.is_some());
    assert!(receipt.block_number.is_some());
    assert_eq!(receipt.from, wallet.address());
    assert!(receipt.to.is_none()); // This is a contract deployment so to should be empty
    assert!(receipt.contract_address.is_some());
    assert!(receipt.cumulative_gas_used > 0.into());
    assert!(receipt.effective_gas_price.unwrap_or_default() > 0.into());
    assert!(receipt.gas_used.unwrap_or_default() > 0.into());
    assert_eq!(receipt.status.unwrap_or_default(), 1.into());
}

#[zilliqa_macros::test]
async fn get_transaction_receipt_sequential_log_indexes(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Deploy a contract that can emit events
    let (hash1, abi) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let receipt1 = network.run_until_receipt(&wallet, hash1, 50).await;
    let contract_address = receipt1.contract_address.unwrap();

    // Call emitEvents() to generate some logs in block 1
    let emit_events = abi.function("emitEvents").unwrap();
    let tx1 = TransactionRequest::new()
        .to(contract_address)
        .data(emit_events.encode_input(&[]).unwrap());

    let tx1_hash = wallet.send_transaction(tx1, None).await.unwrap().tx_hash();

    let receipt1 = network.run_until_receipt(&wallet, tx1_hash, 50).await;

    // Verify logs in first block have sequential indexes starting at 0
    assert!(receipt1.logs.len() > 1);
    for (i, log) in receipt1.logs.iter().enumerate() {
        assert_eq!(log.log_index.unwrap().as_u64(), i as u64);
    }

    // Create another transaction in a new block
    let tx2 = TransactionRequest::new()
        .to(contract_address)
        .data(emit_events.encode_input(&[]).unwrap());

    let tx2_hash = wallet.send_transaction(tx2, None).await.unwrap().tx_hash();

    let receipt2 = network.run_until_receipt(&wallet, tx2_hash, 50).await;

    // Verify logs in second block also start at index 0
    assert!(receipt2.logs.len() > 1);
    for (i, log) in receipt2.logs.iter().enumerate() {
        assert_eq!(log.log_index.unwrap().as_u64(), i as u64);
    }

    // Verify blocks are different
    assert_ne!(receipt1.block_hash, receipt2.block_hash);
}

#[zilliqa_macros::test]
async fn get_logs(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, contract) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
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
            || async {
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
        0u128,
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
            || async {
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

/// Helper method for send transaction tests.
async fn send_transaction(
    network: &mut Network,
    wallet: &Wallet,
    mut tx: TypedTransaction,
) -> (Transaction, TransactionReceipt) {
    wallet.fill_transaction(&mut tx, None).await.unwrap();
    let sig = wallet.signer().sign_transaction_sync(&tx).unwrap();
    let expected_hash = tx.hash(&sig);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    assert_eq!(hash, expected_hash);

    network
        .run_until_async(
            || async {
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

    let tx = wallet.get_transaction(hash).await.unwrap().unwrap();
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();

    (tx, receipt)
}

#[zilliqa_macros::test]
async fn send_legacy_transaction(mut network: Network) {
    let to = H160::random_using(network.rng.lock().unwrap().deref_mut());
    let tx = TransactionRequest::pay(to, 123).into();
    let wallet = network.genesis_wallet().await;
    let (tx, receipt) = send_transaction(&mut network, &wallet, tx).await;

    assert_eq!(tx.transaction_type.unwrap().as_u64(), 0);
    assert_eq!(receipt.to.unwrap(), to);
}

#[zilliqa_macros::test]
async fn send_eip2930_transaction(mut network: Network) {
    let (to, access_list) = {
        let mut rng = network.rng.lock().unwrap();
        let to = H160::random_using(rng.deref_mut());
        let access_list = AccessList(vec![AccessListItem {
            address: H160::random_using(rng.deref_mut()),
            storage_keys: vec![
                H256::random_using(rng.deref_mut()),
                H256::random_using(rng.deref_mut()),
            ],
        }]);
        (to, access_list)
    };
    let tx = Eip2930TransactionRequest::new(TransactionRequest::pay(to, 123), access_list.clone())
        .into();
    let wallet = network.genesis_wallet().await;
    let (tx, receipt) = send_transaction(&mut network, &wallet, tx).await;

    assert_eq!(tx.transaction_type.unwrap().as_u64(), 1);
    assert_eq!(tx.access_list.unwrap(), access_list);
    assert_eq!(receipt.to.unwrap(), to);
}

#[zilliqa_macros::test]
async fn send_eip1559_transaction(mut network: Network) {
    let (to, access_list) = {
        let mut rng = network.rng.lock().unwrap();
        let to = H160::random_using(rng.deref_mut());
        let access_list = AccessList(vec![AccessListItem {
            address: H160::random_using(rng.deref_mut()),
            storage_keys: vec![
                H256::random_using(rng.deref_mut()),
                H256::random_using(rng.deref_mut()),
            ],
        }]);
        (to, access_list)
    };
    let gas_price = network.random_wallet().await.get_gas_price().await.unwrap();
    let tx = Eip1559TransactionRequest::new()
        .to(to)
        .value(456)
        .access_list(access_list.clone())
        .max_fee_per_gas(gas_price)
        .max_priority_fee_per_gas(gas_price)
        .into();
    let wallet = network.genesis_wallet().await;
    let (tx, receipt) = send_transaction(&mut network, &wallet, tx).await;

    assert_eq!(tx.transaction_type.unwrap().as_u64(), 2);
    assert_eq!(tx.access_list.unwrap(), access_list);
    assert_eq!(tx.max_fee_per_gas.unwrap(), gas_price);
    assert_eq!(tx.max_priority_fee_per_gas.unwrap(), gas_price);
    assert_eq!(receipt.to.unwrap(), to);
}

/// Test which sends a legacy transaction, without the replay protection specified by EIP-155.
#[zilliqa_macros::test]
async fn send_legacy_transaction_without_chain_id(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let to = H160::random_using(network.rng.lock().unwrap().deref_mut());
    let tx = TransactionRequest::pay(to, 123);
    let mut tx: TypedTransaction = tx.into();
    wallet.fill_transaction(&mut tx, None).await.unwrap();
    // Clear the chain ID.
    let tx = TypedTransaction::Legacy(TransactionRequest {
        chain_id: None,
        ..tx.into()
    });

    let sig = wallet.signer().sign_hash(tx.sighash()).unwrap();
    let expected_hash = tx.hash(&sig);
    eprintln!("expected: {}", hex::encode(tx.rlp_signed(&sig)));

    // Drop down to the provider, to prevent the wallet middleware from setting the chain ID.
    let hash = wallet
        .provider()
        .send_raw_transaction(tx.rlp_signed(&sig))
        .await
        .unwrap()
        .tx_hash();

    assert_eq!(hash, expected_hash);

    network
        .run_until_async(
            || async {
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

    let tx = wallet.get_transaction(hash).await.unwrap().unwrap();
    assert_eq!(tx.transaction_type.unwrap().as_u64(), 0);
    assert_eq!(tx.chain_id, None);

    let balance = wallet.get_balance(to, None).await.unwrap().as_u128();
    assert_eq!(balance, 123);
}

#[zilliqa_macros::test]
async fn eth_call(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/SetGetContractValue.sol",
        "SetGetContractValue",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    network
        .run_until_async(
            || async {
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

    let getter = abi.function("getUint256").unwrap();

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

#[zilliqa_macros::test]
async fn revert_transaction(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/RevertMe.sol",
        "RevertMe",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();
    let setter = abi.function("revertable").unwrap();
    let getter = abi.function("value").unwrap();

    // First ensure contract works
    let success_call = TransactionRequest::new()
        .to(contract_address)
        .data(setter.encode_input(&[Token::Bool(true)]).unwrap());
    let (_, receipt) = send_transaction(&mut network, &wallet, success_call.into()).await;
    assert_eq!(receipt.status.unwrap().as_u32(), 1);

    // Ensure value was incremented
    let check_call = TransactionRequest::new()
        .to(contract_address)
        .data(getter.selector());
    let value = wallet.call(&check_call.clone().into(), None).await.unwrap();
    let value = getter.decode_output(&value).unwrap()[0]
        .clone()
        .into_int()
        .unwrap();
    assert_eq!(value, 1.into());

    // Next ensure revert fails correctly
    let revert_call = TransactionRequest::new()
        .to(contract_address)
        .data(setter.encode_input(&[Token::Bool(false)]).unwrap())
        .gas(1_000_000); // Pass a gas limit, otherwise estimate_gas is called and fails due to the revert
    let (_, receipt) = send_transaction(&mut network, &wallet, revert_call.into()).await;
    assert_eq!(receipt.status.unwrap().as_u32(), 0);

    // Ensure value was NOT incremented a second time
    let value = wallet.call(&check_call.into(), None).await.unwrap();
    let value = getter.decode_output(&value).unwrap()[0]
        .clone()
        .into_int()
        .unwrap();
    assert_eq!(value, 1.into());
}

#[zilliqa_macros::test]
async fn gas_charged_on_revert(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/RevertMe.sol",
        "RevertMe",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();
    let setter = abi.function("revertable").unwrap();

    let gas_price = wallet.get_gas_price().await.unwrap();

    // Revert on contract failure. Ensure gas is consumed according to execution.
    let balance_before_call = wallet.get_balance(wallet.address(), None).await.unwrap();
    let large_gas_limit = 1_000_000;
    let revert_call = TransactionRequest::new()
        .to(contract_address)
        .data(setter.encode_input(&[Token::Bool(false)]).unwrap())
        .gas(large_gas_limit);
    let (_, receipt) = send_transaction(&mut network, &wallet, revert_call.into()).await;

    assert_eq!(receipt.status.unwrap().as_u32(), 0);
    assert!(receipt.gas_used.is_some());
    let gas_used = receipt.gas_used.unwrap();
    assert!(gas_used > 0.into());
    assert!(gas_used < large_gas_limit.into());
    let balance_after_call = wallet.get_balance(wallet.address(), None).await.unwrap();
    assert_eq!(
        balance_after_call,
        balance_before_call - gas_price * gas_used
    );

    // Revert on out-of-gas. Ensure entire gas limit is consumed.
    let balance_before_call = wallet.get_balance(wallet.address(), None).await.unwrap();

    // Set the gas limit of this transaction to be half of the previous successful call. This guarantees we will fail
    // due to running out of gas.
    let small_gas_limit = gas_used / 2;
    let fail_out_of_gas_call = TransactionRequest::new()
        .to(contract_address)
        .data(setter.encode_input(&[Token::Bool(true)]).unwrap())
        .gas(small_gas_limit);
    let (_, receipt) = send_transaction(&mut network, &wallet, fail_out_of_gas_call.into()).await;

    assert_eq!(receipt.status.unwrap().as_u32(), 0);
    let balance_after_call = wallet.get_balance(wallet.address(), None).await.unwrap();
    assert_eq!(
        balance_after_call,
        balance_before_call - gas_price * small_gas_limit
    );
}

#[zilliqa_macros::test]
async fn nonces_rejected_too_high(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let to: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let mut tx = TransactionRequest::pay(to, 100);

    // Tx nonce of 1 should never get mined
    tx.nonce = Some(1.into());

    // Transform the transaction to its final form, so we can caculate the expected hash.
    let mut tx: TypedTransaction = tx.into();

    wallet.fill_transaction(&mut tx, None).await.unwrap();
    let sig = wallet.signer().sign_transaction_sync(&tx).unwrap();
    let _expected_hash = H256::from_slice(&keccak256(tx.rlp_signed(&sig)));

    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    let wait = network
        .run_until_async(
            || async {
                wallet
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await;

    // Times out trying to mine
    assert!(wait.is_err());
}

#[zilliqa_macros::test]
async fn nonces_respected_ordered(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let to: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    let mut txs_to_send: Vec<TypedTransaction> = Vec::new();
    let tx_send_amount = 10;
    let tx_send_iterations = 100;

    // collect up a bunch of TXs to send at once, but in reverse order
    for i in (0..tx_send_iterations).rev() {
        let mut tx = TransactionRequest::pay(to, tx_send_amount);
        tx.nonce = Some(i.into());
        let mut tx: TypedTransaction = tx.into();

        wallet.fill_transaction(&mut tx, None).await.unwrap();
        txs_to_send.push(tx);
    }

    // collect the promises and await on them
    let mut promises = Vec::new();

    // Send all of them
    for tx in txs_to_send {
        let prom = wallet.send_transaction(tx, None);
        promises.push(prom);
    }

    // Wait for all of them to be completed
    join_all(promises).await;

    // Wait until target account has got all the TXs
    let wait = network
        .run_until_async(
            || async {
                wallet.get_balance(to, None).await.unwrap()
                    == (tx_send_amount * tx_send_iterations).into()
            },
            10000,
        )
        .await;

    // doesn't time out trying to mine
    assert!(wait.is_ok());
}

#[zilliqa_macros::test]
async fn priority_fees_tx(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let to: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    let mut txs_to_send: Vec<TypedTransaction> = Vec::new();
    let tx_send_amount = 10;
    let tx_send_iterations = 10;

    // collect up a bunch of TXs to send at once, with two per nonce (one with a priority fee)
    // but starting from nonce 1 to allow the mempool time to see them all without being able to mine them yet
    for i in 1..tx_send_iterations {
        // This first one with a transfer amount of 1 should never get mined
        let mut tx = TransactionRequest::pay(to, 1);
        tx.nonce = Some(i.into());
        let mut tx: TypedTransaction = tx.into();
        wallet.fill_transaction(&mut tx, None).await.unwrap();
        let next_gas_price = tx.gas_price().unwrap() * 2; // double gas price for next one
        txs_to_send.push(tx);

        // Second priority tx
        let mut tx = TransactionRequest::pay(to, tx_send_amount);
        tx.nonce = Some(i.into());
        tx.gas_price = Some(next_gas_price);
        let mut tx: TypedTransaction = tx.into();

        wallet.fill_transaction(&mut tx, None).await.unwrap();
        txs_to_send.push(tx);
    }

    // collect the promises and await on them
    let mut promises = Vec::new();
    let txns_count = txs_to_send.len();
    // Send all of them
    for tx in txs_to_send {
        let prom = wallet.send_transaction(tx, None);
        promises.push(prom);
    }

    // Wait for all of them to be completed. We need to tick since they get broadcast around
    // as messages too and you can't guarantee which miner will try to create a block
    for prom in promises {
        let _hash = prom.await.unwrap().tx_hash();
        network.tick().await;
    }

    // Give enough time for all transactions to reach possible proposer
    for _ in 0..10 * txns_count {
        network.tick().await;
    }

    // Now send the first one
    let mut tx = TransactionRequest::pay(to, tx_send_amount);
    tx.nonce = Some(0.into());
    let mut tx: TypedTransaction = tx.into();

    wallet.fill_transaction(&mut tx, None).await.unwrap();
    wallet.send_transaction(tx, None).await.unwrap();

    // Wait until target account has got all the TXs
    let wait = network
        .run_until_async(
            || async {
                wallet.get_balance(to, None).await.unwrap()
                    == (tx_send_amount * tx_send_iterations).into()
            },
            100,
        )
        .await;

    // doesn't time out trying to mine
    assert!(wait.is_ok());
}

#[zilliqa_macros::test]
async fn pending_transaction_is_returned_by_get_transaction_by_hash(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let provider = wallet.provider();

    // Send a transaction.
    let hash = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    // Check the transaction is returned with null values for the block.
    let tx = wallet.get_transaction(hash).await.unwrap().unwrap();
    assert_eq!(tx.block_hash, None);
    assert_eq!(tx.block_number, None);

    // Wait for the transaction to be mined.
    network
        .run_until_async(
            || async {
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

    // Check the transaction is returned with non-null values for the block.
    let tx = wallet.get_transaction(hash).await.unwrap().unwrap();
    assert!(tx.block_hash.is_some());
    assert!(tx.block_number.is_some());
}

#[zilliqa_macros::test]
async fn get_transaction_by_index(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Send transaction in reverse nonce order to ensure they land in the same block
    let h1 = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10).nonce(1), None)
        .await
        .unwrap()
        .tx_hash();

    let h2 = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10).nonce(0), None)
        .await
        .unwrap()
        .tx_hash();

    let r1 = network.run_until_receipt(&wallet, h1, 50).await;
    let r2 = network.run_until_receipt(&wallet, h2, 50).await;

    // NOTE: they are not always in the same block
    if r1.block_hash == r2.block_hash {
        let block_hash = r1.block_hash.unwrap();
        let block_number = r1.block_number.unwrap();

        let txn = wallet
            .get_transaction_by_block_and_index(block_hash, 0u64.into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.hash, h2);

        let txn = wallet
            .get_transaction_by_block_and_index(block_number, 1u64.into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.hash, h1);
    } else {
        let block_hash = r2.block_hash.unwrap();
        let block_number = r1.block_number.unwrap();

        let txn = wallet
            .get_transaction_by_block_and_index(block_hash, 0u64.into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.hash, h2);

        let txn = wallet
            .get_transaction_by_block_and_index(block_number, 0u64.into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.hash, h1);
    }
}

#[zilliqa_macros::test]
async fn block_subscription(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let mut block_stream: ethers::providers::SubscriptionStream<
        '_,
        LocalRpcClient,
        ethers::types::Block<H256>,
    > = wallet.subscribe_blocks().await.unwrap();
    network.run_until_block(&wallet, 3.into(), 100).await;

    // Assert the stream contains next 3 blocks.
    assert_eq!(
        block_stream.next().await.unwrap().number.unwrap().as_u64(),
        1
    );
    assert_eq!(
        block_stream.next().await.unwrap().number.unwrap().as_u64(),
        2
    );
    assert_eq!(
        block_stream.next().await.unwrap().number.unwrap().as_u64(),
        3
    );

    assert!(block_stream.unsubscribe().await.unwrap());
}

#[zilliqa_macros::test]
async fn logs_subscription(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, contract) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();

    // Our filtering logic is tested above by the `eth_getLogs` test, so in this test we just check whether logs are
    // returned at all from the subscription.
    let mut log_stream = wallet.subscribe_logs(&Filter::new()).await.unwrap();

    let emit_events = contract.function("emitEvents").unwrap();
    let call_tx = TransactionRequest::new()
        .to(contract_address)
        .data(emit_events.encode_input(&[]).unwrap());

    let call_tx_hash = wallet
        .send_transaction(call_tx, None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, call_tx_hash, 50).await;

    assert_eq!(log_stream.next().await.unwrap().address, contract_address);
    assert_eq!(log_stream.next().await.unwrap().address, contract_address);

    assert!(log_stream.unsubscribe().await.unwrap());
}

#[zilliqa_macros::test]
async fn new_transaction_subscription(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let mut txn_stream = wallet.subscribe_full_pending_txs().await.unwrap();
    let mut hash_stream = wallet.subscribe_pending_txs().await.unwrap();

    let txn = TransactionRequest::pay(H160::random(), 10);
    let txn = wallet.send_transaction(txn, None).await.unwrap();

    // Note we don't wait for the transaction to be mined - The subscriptions should already contain this transaction.

    assert_eq!(txn_stream.next().await.unwrap().hash, txn.tx_hash());
    assert_eq!(hash_stream.next().await.unwrap(), txn.tx_hash());

    assert!(txn_stream.unsubscribe().await.unwrap());
    assert!(hash_stream.unsubscribe().await.unwrap());
}

#[zilliqa_macros::test]
async fn get_accounts_with_nonexistent_params(mut network: Network) {
    let client = network.rpc_client(0).await.unwrap();
    // Attempt to call eth_accounts (as a random example) with no parameters at all and check that the
    // call succeeds and the result is empty.
    let result = client
        .request_optional::<(), Vec<Address>>("eth_accounts", None)
        .await
        .unwrap();

    assert!(result.is_empty());
}

#[zilliqa_macros::test]
async fn get_accounts_with_extra_args(mut network: Network) {
    let client = network.rpc_client(0).await.unwrap();
    // Attempt to call eth_accounts (as a random example) with no parameters at all and check that the
    // call succeeds and the result is empty.
    let result = client
        .request_optional::<Vec<&str>, Vec<Address>>("eth_accounts", Some(vec!["extra"]))
        .await;

    assert!(result.is_err());
}

#[zilliqa_macros::test]
async fn deploy_deterministic_deployment_proxy(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let signer: H160 = "0x3fab184622dc19b6109349b94811493bf2a45362"
        .parse()
        .unwrap();

    let gas_price = 100000000000u128;
    let gas = 100000u128;

    // Send the signer enough money to cover the deployment.
    let tx = TransactionRequest::pay(signer, gas_price * gas);
    send_transaction(&mut network, &wallet, tx.into()).await;

    // Transaction from https://github.com/Arachnid/deterministic-deployment-proxy.
    let tx = TransactionRequest::new()
        .nonce(0)
        .gas_price(gas_price)
        .gas(gas)
        .value(0)
        .data(hex!("604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3"));
    let tx = TypedTransaction::Legacy(tx);
    let signature = Signature {
        r: hex!("2222222222222222222222222222222222222222222222222222222222222222").into(),
        s: hex!("2222222222222222222222222222222222222222222222222222222222222222").into(),
        v: 27,
    };
    let raw_tx = tx.rlp_signed(&signature);
    let hash = wallet.send_raw_transaction(raw_tx).await.unwrap().tx_hash();

    let receipt = network.run_until_receipt(&wallet, hash, 150).await;

    assert_eq!(receipt.from, signer);
    assert_eq!(
        receipt.contract_address.unwrap(),
        "0x4e59b44847b379578588920ca78fbf26c0b4956c"
            .parse()
            .unwrap()
    );
}

#[zilliqa_macros::test]
async fn test_send_transaction_errors(mut network: Network) {
    let wallet = network.random_wallet().await;
    network.run_until_block(&wallet, 3.into(), 70).await;

    async fn send_transaction_get_error(wallet: &Wallet, tx: TransactionRequest) -> (i64, String) {
        let result = wallet.send_transaction(tx, None).await;
        assert!(result.is_err());
        let val = result.unwrap_err();
        let err = val.as_error_response().unwrap();
        (err.code, err.message.to_string())
    }
    async fn send_raw_transaction_get_error(wallet: &Wallet, tx: Bytes) -> (i64, String) {
        let result = wallet.send_raw_transaction(tx).await;
        assert!(result.is_err());
        let val = result.unwrap_err();
        let err = val.as_error_response().unwrap();
        (err.code, err.message.to_string())
    }
    let gas_price = 100000000000u128;
    let gas = 100000u128;

    // Give the signer some funds.
    let tx = TransactionRequest::pay(wallet.address(), 2 * gas_price * gas);
    let genesis_wallet = network.genesis_wallet().await;
    send_transaction(&mut network, &genesis_wallet, tx.into()).await;

    // Deliberately set too low a gas fee
    {
        let tx = TransactionRequest::pay(H160::random(), 10).gas(1);
        let (code, msg) = send_transaction_get_error(&wallet, tx).await;
        assert_eq!(code, -32602);
        assert!(msg.to_lowercase().contains("gas"));
    }
    {
        let tx = TransactionRequest::pay(H160::random(), gas_price * gas)
            .gas_price(gas_price)
            .gas(gas);
        let sig = wallet.signer().sign_hash(tx.sighash()).unwrap();
        let mut signed = tx.rlp_signed(&sig).iter().cloned().collect::<Vec<u8>>();
        // Corrupt the transaction data.
        signed[1] += 2;
        let (code, _) = send_raw_transaction_get_error(&wallet, signed.into()).await;
        assert_eq!(code, -32603);
    }
    // it would be nice to test bad signatures, but generating one without
    // causing other spurious errors appears to be hard.
    {
        let tx = TransactionRequest::pay(H160::random(), 200 * gas_price * gas).nonce(547);
        let (code, msg) = send_transaction_get_error(&wallet, tx).await;
        assert_eq!(code, -32603);
        assert!(msg.to_lowercase().contains("funds"));
    }
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncingStruct {
    pub starting_block: u64,
    pub current_block: u64,
    pub highest_block: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum SyncingResult {
    Bool(bool),
    Struct(SyncingStruct),
}

#[zilliqa_macros::test]
async fn test_eth_syncing(mut network: Network) {
    let client = network.rpc_client(0).await.unwrap();
    let wallet = network.random_wallet().await;
    network.run_until_block(&wallet, 3.into(), 70).await;

    let result = client
        .request_optional::<(), SyncingResult>("eth_syncing", None)
        .await
        .unwrap();
    assert_eq!(result, SyncingResult::Bool(false))
}

#[zilliqa_macros::test]
async fn get_block_receipts(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // Deploy a contract to generate a transaction
    let (hash1, _) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let receipt1 = network.run_until_receipt(&wallet, hash1, 50).await;
    let block_hash = receipt1.block_hash.unwrap();

    // Get receipts by block hash
    let receipts: Vec<TransactionReceipt> = provider
        .request("eth_getBlockReceipts", [block_hash])
        .await
        .unwrap();

    assert_eq!(receipts.len(), 1);
    assert!(receipts.iter().any(|r| r.transaction_hash == hash1));

    // Verify receipts match individual receipt queries
    let individual1 = provider
        .get_transaction_receipt(hash1)
        .await
        .unwrap()
        .unwrap();

    assert!(receipts.contains(&individual1));
}

#[zilliqa_macros::test]
async fn test_block_filter(mut network: Network) {
    println!("Starting block filter test");
    let wallet = network.random_wallet().await;
    let provider = wallet.provider();

    // Create a new block filter
    println!("Creating new block filter");
    let filter_id: u128 = provider.request("eth_newBlockFilter", ()).await.unwrap();
    println!("Created filter with ID: {}", filter_id);

    // Generate some blocks
    println!("Generating blocks");
    network.run_until_block(&wallet, 3.into(), 50).await;
    println!("Generated blocks");

    // Get filter changes - should return the new block hashes
    println!("Getting filter changes");
    let changes_result: serde_json::Value = provider
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<H256> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes", changes.len());

    // We should have at least 2 new blocks (not counting the block at which we created the filter)
    assert!(!changes.is_empty());
    assert!(changes.len() >= 2);

    // Changes should be valid block hashes
    println!("Verifying block hashes");
    for hash in &changes {
        println!("Checking block hash: {}", hash);
        let block = provider
            .get_block(BlockId::Hash(*hash))
            .await
            .unwrap()
            .unwrap();
        block.number.unwrap();
    }

    // Calling get_filter_changes again should return empty as we've already retrieved the changes
    println!("Getting filter changes second time");
    let changes_result: serde_json::Value = provider
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<H256> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes on second call", changes.len());
    dbg!(&changes);
    assert!(changes.is_empty());

    println!("Removing filter");
    let filter_removed_successfully: bool = provider
        .request("eth_uninstallFilter", [filter_id])
        .await
        .unwrap();
    println!("Filter removed: {}", filter_removed_successfully);
    assert!(filter_removed_successfully);
}

#[zilliqa_macros::test]
async fn test_pending_transaction_filter(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // Create a new pending transaction filter
    println!("Creating new pending transaction filter");
    let filter_id: u128 = provider
        .request("eth_newPendingTransactionFilter", ())
        .await
        .unwrap();
    println!("Created filter with ID: {}", filter_id);

    // Send a transaction.
    let hash = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    // Get filter changes - should return the pending transaction hashes
    println!("Getting filter changes");
    let changes_result: serde_json::Value = provider
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<H256> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes", changes.len());

    assert!(changes.contains(&hash));

    // Calling get_filter_changes again should return empty
    println!("Getting filter changes second time");
    let changes_result: serde_json::Value = provider
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<H256> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes on second call", changes.len());
    assert!(changes.is_empty());
}

#[zilliqa_macros::test]
async fn test_log_filter(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    let (hash, contract) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();

    // Create a filter for contract events
    println!("Creating event filter");
    let filter = json!({
        "fromBlock": "latest",
        "address": contract_address,
    });
    let filter_id: u128 = provider.request("eth_newFilter", [filter]).await.unwrap();
    println!("Created filter with ID: {}", filter_id);

    let emit_events = contract.function("emitEvents").unwrap();
    let call_tx = TransactionRequest::new()
        .to(contract_address)
        .data(emit_events.encode_input(&[]).unwrap());

    let call_tx_hash = wallet
        .send_transaction(call_tx, None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, call_tx_hash, 50).await;

    // Get filter changes
    println!("Getting filter changes");
    let logs_result: serde_json::Value = provider
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    dbg!(&logs_result);
    let logs: Vec<serde_json::Value> = serde_json::from_value(logs_result).unwrap();
    println!("Got {} logs", logs.len());

    assert_eq!(logs.len(), 2);

    // Test get_filter_logs
    println!("Testing get_filter_logs");
    let logs_via_get_result: serde_json::Value = provider
        .request("eth_getFilterLogs", [filter_id])
        .await
        .unwrap();
    let logs_via_get: Vec<serde_json::Value> = serde_json::from_value(logs_via_get_result).unwrap();
    assert_eq!(logs, logs_via_get);

    // Calling get_filter_changes again should return empty
    println!("Getting filter changes second time");
    let changes_result: serde_json::Value = provider
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<serde_json::Value> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes on second call", changes.len());
    assert!(changes.is_empty());

    println!("Removing filter");
    let filter_removed_successfully: bool = provider
        .request("eth_uninstallFilter", [filter_id])
        .await
        .unwrap();
    println!("Filter removed: {}", filter_removed_successfully);
    assert!(filter_removed_successfully);
}

#[zilliqa_macros::test]
async fn test_invalid_filter_id(mut network: Network) {
    println!("Starting invalid filter ID test");
    let wallet = network.random_wallet().await;
    let provider = wallet.provider();

    // Try to get changes for non-existent filter
    println!("Attempting to get changes for invalid filter ID");
    let result = provider
        .request::<_, Value>("eth_getFilterChanges", ["0x123"])
        .await;
    assert!(result.is_err());
}

#[zilliqa_macros::test]
async fn test_uninstall_filter(mut network: Network) {
    println!("Starting uninstall filter test");
    let wallet = network.random_wallet().await;
    let provider = wallet.provider();

    // Create a new filter
    println!("Creating new block filter");
    let filter_id: u128 = provider.request("eth_newBlockFilter", ()).await.unwrap();
    println!("Created filter with ID: {}", filter_id);

    // Verify filter exists by using it
    println!("Verifying filter exists");
    let _changes: Vec<H256> = provider
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    println!("Filter verified");

    // Successfully uninstall the filter
    println!("Uninstalling filter");
    let filter_removed: bool = provider
        .request("eth_uninstallFilter", [filter_id])
        .await
        .unwrap();
    println!("Filter removed: {}", filter_removed);
    assert!(filter_removed);

    // Verify filter no longer exists
    println!("Verifying filter no longer exists");
    let result = provider
        .request::<_, Value>("eth_getFilterChanges", [filter_id])
        .await;
    assert!(result.is_err());
}

#[zilliqa_macros::test]
async fn get_block_by_number(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // Make sure there's at least one block to retrieve
    network.run_until_block(&wallet, 2u64.into(), 50).await;

    // Get the latest block number
    let latest_number = provider.get_block_number().await.unwrap();

    // Query eth_getBlockByNumber with 'latest', full transactions requested
    let block = provider
        .request::<_, serde_json::Value>("eth_getBlockByNumber", (latest_number, true))
        .await
        .unwrap();

    // Some block fields should always be present
    assert_eq!(
        block["number"],
        serde_json::json!(format!("0x{:x}", latest_number.as_u64()))
    );
    assert!(block["hash"].as_str().unwrap().starts_with("0x"));
    assert!(block["parentHash"].as_str().unwrap().starts_with("0x"));
    assert_eq!(block["uncles"], serde_json::json!([])); // No uncles in ZQ2

    // Specific required fields
    // difficulty: 0x0
    assert_eq!(block["difficulty"], serde_json::json!("0x0"));

    // sha3Uncles: RLP( [] ), 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347
    assert_eq!(
        block["sha3Uncles"],
        serde_json::json!("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
    );

    // miner is a proper address, not "None"
    let miner = block["miner"].as_str().unwrap();
    assert!(
        miner.starts_with("0x") && miner.len() == 42,
        "Miner field is not a 20-byte address: {miner}"
    );

    // Some other typical fields
    assert!(block["transactions"].is_array());

    // Block gasLimit/gasUsed, timestamp, size are all nonzero/zero
    assert!(block["gasLimit"].as_str().unwrap().starts_with("0x"));
    assert!(block["gasUsed"].as_str().unwrap().starts_with("0x"));
    assert!(block["timestamp"].as_str().unwrap().starts_with("0x"));
    assert!(u64::from_str_radix(&block["size"].as_str().unwrap()[2..], 16).unwrap() > 0);
}
