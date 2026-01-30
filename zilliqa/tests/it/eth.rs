use alloy::{
    consensus::TypedTransaction,
    eips::{BlockId, BlockNumberOrTag},
    network::TransactionBuilder,
    primitives::{Address, B256, Bytes, I256, TxHash, U64, U256, keccak256},
    providers::{Provider, WalletProvider},
    rpc::{
        client::RpcClientInner,
        types::{AccessList, AccessListItem, Filter, TransactionReceipt, TransactionRequest},
    },
    sol,
    sol_types::SolEvent,
};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_stream::StreamExt as _;
use zilliqa::api::to_hex::ToHex;

use crate::{Network, Wallet, deploy_contract};

sol!(
    #[sol(rpc)]
    "tests/it/contracts/CallMe.sol"
);
#[zilliqa_macros::test]
async fn call_block_number(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (address, _hash) = deploy_contract(
        "tests/it/contracts/CallMe.sol",
        "CallMe",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    // Query the current block number with an `eth_call`.
    let callme = CallMe::new(address, &wallet);
    let block_number = callme.currentBlock().call().await.unwrap().to::<u64>();

    // Verify it is correct.
    let expected_block_number = wallet.get_block_number().await.unwrap();
    assert_eq!(block_number, expected_block_number);

    // Advance the network
    network
        .run_until_block_finalized(expected_block_number, 100)
        .await
        .unwrap();

    // Query the current block number with an `eth_call`.
    let new_block_number = callme.currentBlock().call().await.unwrap().to::<u64>();

    // Verify it is correct.
    let expected_block_number = wallet.get_block_number().await.unwrap();
    assert_eq!(new_block_number, expected_block_number);

    // Query the block number at the old block with an `eth_call`.

    let old_block_number = callme
        .currentBlock()
        .call()
        .block(BlockId::number(block_number))
        .await
        .unwrap()
        .to::<u64>();

    // Verify it used the state from the old block.
    assert_eq!(old_block_number, block_number);
}

#[zilliqa_macros::test]
async fn get_block_transaction_count(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

    async fn count_by_number(provider: &RpcClientInner, number: Option<u64>) -> u64 {
        let number = number.map_or("latest".to_string(), |n| format!("{:#04x}", n));
        provider
            .request::<_, U64>("eth_getBlockTransactionCountByNumber", [number])
            .await
            .unwrap()
            .to::<u64>()
    }

    async fn count_by_hash(provider: &RpcClientInner, hash: TxHash) -> u64 {
        provider
            .request::<_, U64>("eth_getBlockTransactionCountByHash", [json!(hash)])
            .await
            .unwrap()
            .to::<u64>()
    }

    // Send a transaction.
    let hash = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(Address::random())
                .value(U256::from(10)),
        )
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;

    let block_hash = receipt.block_hash.unwrap();
    let block_number = receipt.block_number.unwrap();

    // Check the previous block has a transaction count of zero.
    let count = count_by_number(provider, Some(block_number - 1)).await;
    assert_eq!(count, 0);

    // Check this block has a transaction count of one.
    let count = count_by_number(provider, Some(block_number)).await;
    assert_eq!(count, 1);
    let count = count_by_hash(provider, block_hash).await;
    assert_eq!(count, 1);

    // The latest block is the one with our transaction, because we stopped running the network after our receipt
    // appeared. So the latest block should also have a count of one.
    let count = count_by_number(provider, None).await;
    assert_eq!(count, 1);
}

#[zilliqa_macros::test]
async fn get_transaction_count_pending(mut network: Network) {
    let wallet_1 = network.genesis_wallet().await;
    let wallet_2 = network.random_wallet().await;

    async fn get_count(address: Address, provider: &RpcClientInner, number: &str) -> u64 {
        provider
            .request::<_, U64>("eth_getTransactionCount", (address.to_hex(), number))
            .await
            .unwrap()
            .to::<u64>()
    }

    // Both wallets should have no transactions pending.
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 0);
    let count = get_count(
        wallet_2.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 0);

    // Send a transaction from wallet 1 to wallet 2.
    let hash_1 = *wallet_1
        .send_transaction(
            TransactionRequest::default()
                .to(wallet_2.default_signer_address())
                .value(U256::from(10))
                .nonce(0),
        )
        .await
        .unwrap()
        .tx_hash();

    // Wallet 1 should now have 1 transaction pending, and no transactions in the latest block.
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 1);
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "latest",
    )
    .await;
    assert_eq!(count, 0);

    // Send a transaction from wallet 1 to wallet 2.
    //
    let hash_2 = *wallet_1
        .send_transaction(
            TransactionRequest::default()
                .to(wallet_2.default_signer_address())
                .value(U256::from(10))
                .nonce(1),
        )
        .await
        .unwrap()
        .tx_hash();

    // Wallet 1 should now have 2 transactions pending, and still no transactions in the latest block.
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 2);
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "latest",
    )
    .await;
    assert_eq!(count, 0);

    // Ensure transaction count is account specific.
    let count = get_count(
        wallet_2.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 0);

    // Process pending transaction
    network.run_until_receipt(&wallet_2, &hash_2, 100).await;
    network.run_until_receipt(&wallet_1, &hash_1, 100).await;

    // Wallet 1 should no longer have any pending transactions, and should have 2 transactions in the
    // latest block, leading to 2 returned for both "pending" and "latest".
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 2);
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "latest",
    )
    .await;
    assert_eq!(count, 2);

    // Send a transaction from wallet 1 to wallet 2.
    let _ = wallet_1
        .send_transaction(
            TransactionRequest::default()
                .to(wallet_2.default_signer_address())
                .value(U256::from(10))
                .nonce(3),
        )
        .await
        .unwrap()
        .tx_hash();

    // Wallet 1 should no longer have any pending transactions, and should have 2 transactions in the
    // latest block, leading to 2 returned for both "pending" and "latest".
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 2);

    // Send a transaction from wallet 1 to wallet 2.
    let _ = wallet_1
        .send_transaction(
            TransactionRequest::default()
                .to(wallet_2.default_signer_address())
                .value(U256::from(10))
                .nonce(2),
        )
        .await
        .unwrap()
        .tx_hash();

    // Wallet 1 should no longer have any pending transactions, and should have 2 transactions in the
    // latest block, leading to 2 returned for both "pending" and "latest".
    let count = get_count(
        wallet_1.default_signer_address(),
        wallet_1.client(),
        "pending",
    )
    .await;
    assert_eq!(count, 4);
}

#[zilliqa_macros::test]
async fn get_account_transaction_count(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

    async fn count_at_block(provider: &RpcClientInner, params: (Address, U64)) -> u64 {
        provider
            .request::<(Address, U64), U64>("eth_getTransactionCount", params)
            .await
            .unwrap()
            .to::<u64>()
    }

    // Send a transaction.
    let hash = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(Address::random())
                .value(U256::from(10)),
        )
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;
    let block_number = receipt.block_number.unwrap();

    // Check the wallet has a transaction count of one.
    let count = count_at_block(
        provider,
        (wallet.default_signer_address(), U64::from(block_number)),
    )
    .await;
    assert_eq!(count, 1);

    // Check the wallet has a transaction count of zero at the previous block
    let count = count_at_block(
        provider,
        (wallet.default_signer_address(), U64::from(block_number - 1)),
    )
    .await;
    assert_eq!(count, 0);
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/EmitEvents.sol"
);
#[zilliqa_macros::test]
async fn get_transaction_receipt(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Deploy a contract to generate a transaction receipt
    let (address, receipt) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    dbg!(&receipt);

    // Verify the transaction receipt fields
    // assert_eq!(receipt.transaction_hash, hash);
    assert!(receipt.block_hash.is_some());
    assert!(receipt.block_number.is_some());
    assert_eq!(receipt.from, wallet.default_signer_address());
    assert!(receipt.to.is_none()); // This is a contract deployment so to should be empty
    assert_eq!(receipt.contract_address.unwrap(), address);
    assert!(receipt.effective_gas_price > 0);
    assert!(receipt.gas_used > 0);
    assert!(receipt.inner.cumulative_gas_used() > 0);
    assert!(receipt.status());
}

#[zilliqa_macros::test]
async fn get_transaction_receipt_sequential_log_indexes(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Deploy a contract that can emit events
    let (addr, _) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;
    let contract = EmitEvents::new(addr, &wallet);

    // Call emitEvents() to generate some logs in block 1
    let tx1_hash = *contract.emitEvents().send().await.unwrap().tx_hash();
    let receipt1 = network.run_until_receipt(&wallet, &tx1_hash, 50).await;

    // Verify logs in first block have sequential indexes starting at 0
    assert!(receipt1.logs().len() > 1);
    for (i, log) in receipt1.logs().iter().enumerate() {
        assert_eq!(log.log_index.unwrap(), i as u64);
    }

    // Create another transaction in a new block
    let tx2_hash = *contract.emitEvents().send().await.unwrap().tx_hash();
    let receipt2 = network.run_until_receipt(&wallet, &tx2_hash, 50).await;

    // Verify logs in second block also start at index 0
    assert!(receipt2.logs().len() > 1);
    for (i, log) in receipt2.logs().iter().enumerate() {
        assert_eq!(log.log_index.unwrap(), i as u64);
    }

    // Verify blocks are different
    assert_ne!(receipt1.block_hash, receipt2.block_hash);
}

#[zilliqa_macros::test]
async fn get_logs(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (contract_address, _) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;
    let contract = EmitEvents::new(contract_address, &wallet);

    let hash = *contract.emitEvents().send().await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 50).await;

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
            .get_logs(&base.clone().address(wallet.default_signer_address()))
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
    // let transfer = contract.event("Transfer").unwrap().signature();
    // let approval = contract.event("Approval").unwrap().signature();
    // let nonsense = H256::from_low_u64_be(123);

    let transfer = EmitEvents::Transfer::SIGNATURE_HASH;
    let approval = EmitEvents::Approval::SIGNATURE_HASH;
    let nonsense = B256::random();

    // Filter by topic0.
    assert_eq!(
        wallet
            .get_logs(&base.clone().event_signature(transfer))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wallet
            .get_logs(&base.clone().event_signature(approval))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wallet
            .get_logs(&base.clone().event_signature(nonsense))
            .await
            .unwrap()
            .len(),
        0
    );

    // Multiple topics in the same position act as an OR filter.
    assert_eq!(
        wallet
            .get_logs(&base.clone().event_signature(vec![transfer, approval]))
            .await
            .unwrap()
            .len(),
        2
    );

    // Including extra topics in the OR filter doesn't make a difference.
    assert_eq!(
        wallet
            .get_logs(
                &base
                    .clone()
                    .event_signature(vec![transfer, approval, nonsense])
            )
            .await
            .unwrap()
            .len(),
        2
    );

    // Filter by topic1 (same value for both logs).
    let one = B256::with_last_byte(1);
    assert_eq!(
        wallet
            .get_logs(&base.clone().topic1(one))
            .await
            .unwrap()
            .len(),
        2
    );

    // // Filter by topic2 (different value for each log).
    let two = B256::with_last_byte(2);
    let three = B256::with_last_byte(3);
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
                    .event_signature(vec![transfer, approval])
                    .topic1(one)
                    .topic2(vec![two, three])
            )
            .await
            .unwrap()
            .len(),
        2
    );
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/Storage.sol",
);
#[zilliqa_macros::test]
async fn get_storage_at(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getstorageat.
    let (contract_address, receipt) = deploy_contract(
        "tests/it/contracts/Storage.sol",
        "Storage",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = Storage::new(contract_address, &wallet);
    let value = wallet
        .get_storage_at(contract_address, U256::ZERO)
        .await
        .unwrap();

    assert_eq!(value, U256::from(1234));

    // Calculate the storage position with keccak(LeftPad32(key, 0), LeftPad32(map position, 0))
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(receipt.from.as_slice());
    bytes.extend_from_slice(&[0; 31]);
    bytes.push(1);
    let position = U256::from_be_slice(keccak256(bytes).0.as_slice());

    let value = wallet
        .get_storage_at(contract_address, position)
        .await
        .unwrap();
    assert_eq!(value, U256::from(5678));

    // Save the current block number
    let old_block_number = wallet.get_block_number().await.unwrap();

    // Modify the contract state.
    let hash = *contract.update().send().await.unwrap().tx_hash();
    let _ = network.run_until_receipt(&wallet, &hash, 50).await;

    // verify the new state
    let value = wallet
        .get_storage_at(contract_address, U256::ZERO)
        .await
        .unwrap();
    assert_eq!(value, U256::from(9876));

    // verify that the state at the old block can still be fetched correctly
    let value = wallet
        .get_storage_at(contract_address, U256::ZERO)
        .block_id(BlockId::number(old_block_number))
        .await
        .unwrap();
    assert_eq!(value, U256::from(1234));
}

// /// Helper method for send transaction tests.
async fn send_transaction(
    network: &mut Network,
    wallet: &Wallet,
    tx: TypedTransaction,
) -> TransactionReceipt {
    let hash = *wallet.send_transaction(tx.into()).await.unwrap().tx_hash();
    network.run_until_receipt(wallet, &hash, 200).await
}

#[zilliqa_macros::test]
async fn send_legacy_transaction(mut network: Network) {
    let gas_price = network.random_wallet().await.get_gas_price().await.unwrap();
    let to = Address::random();
    let tx: TypedTransaction = TransactionRequest::default()
        .to(to)
        .value(U256::from(123))
        .nonce(0)
        .gas_limit(21_000)
        .gas_price(gas_price)
        .build_legacy()
        .unwrap()
        .into();
    assert!(tx.tx_type().is_legacy());

    let wallet = network.genesis_wallet().await;
    let receipt = send_transaction(&mut network, &wallet, tx).await;
    assert_eq!(receipt.to.unwrap(), to)
}

#[zilliqa_macros::test]
async fn send_eip2930_transaction(mut network: Network) {
    let gas_price = network.random_wallet().await.get_gas_price().await.unwrap();
    let access_list = AccessList(vec![AccessListItem {
        address: Address::random(),
        storage_keys: vec![TxHash::random(), TxHash::random()],
    }]);

    let wallet = network.genesis_wallet().await;

    let tx: TypedTransaction = TransactionRequest::default()
        .to(wallet.default_signer_address())
        .value(U256::from(123))
        .nonce(0)
        .with_chain_id(33468)
        .gas_limit(28_000)
        .gas_price(gas_price)
        .access_list(access_list.clone())
        .build_2930()
        .unwrap()
        .into();

    assert!(tx.tx_type().is_eip2930());
    assert_eq!(tx.eip2930().unwrap().access_list, access_list);

    let receipt = send_transaction(&mut network, &wallet, tx).await;

    assert_eq!(receipt.to.unwrap(), wallet.default_signer_address());
}

#[zilliqa_macros::test]
async fn send_eip1559_transaction(mut network: Network) {
    let gas_price = network.random_wallet().await.get_gas_price().await.unwrap();
    let access_list = AccessList(vec![AccessListItem {
        address: Address::random(),
        storage_keys: vec![TxHash::random(), TxHash::random()],
    }]);

    let wallet = network.genesis_wallet().await;
    let tx: TypedTransaction = TransactionRequest::default()
        .to(Address::random())
        .value(U256::from(456))
        .nonce(0)
        .with_chain_id(33468)
        .access_list(access_list.clone())
        .max_fee_per_gas(gas_price)
        .max_priority_fee_per_gas(gas_price)
        .gas_limit(28_000)
        .build_1559()
        .unwrap()
        .into();

    assert!(tx.tx_type().is_eip1559());
    assert_eq!(tx.eip1559().unwrap().access_list, access_list);
    assert_eq!(tx.eip1559().unwrap().max_fee_per_gas, gas_price);
    assert_eq!(tx.eip1559().unwrap().max_priority_fee_per_gas, gas_price);

    let receipt = send_transaction(&mut network, &wallet, tx).await;

    assert_ne!(receipt.to.unwrap(), wallet.default_signer_address());
}

// /// Test which sends a legacy transaction, without the replay protection specified by EIP-155.
// #[zilliqa_macros::test]
// async fn send_legacy_transaction_without_chain_id(mut network: Network) {
//     let wallet = network.genesis_wallet().await;
//     let gas_price = wallet.get_gas_price().await.unwrap();

//     let to = Address::random();
//     let tx = TransactionRequest::default()
//         .to(to)
//         .nonce(0)
//         .gas_limit(21_000)
//         .gas_price(gas_price)
//         .value(U256::from(123))
//         .build_legacy()
//         .unwrap();

//     // Clear the chain ID.
//     let tx = TxLegacy {
//         chain_id: None,
//         ..tx
//     };

//     // let sig = wallet.signer().sign_hash(tx.sighash()).unwrap();
//     // let expected_hash = tx.hash(&sig);
//     // eprintln!("expected: {}", hex::encode(tx.rlp_signed(&sig)));

//     let signed = wallet.sign_transaction(tx).await.unwrap();

//     // Drop down to the provider, to prevent the wallet middleware from setting the chain ID.
//     let hash = *wallet
//         .send_raw_transaction(&signed)
//         .await
//         .unwrap()
//         .tx_hash();

//     // assert_eq!(hash, expected_hash);
//     network.run_until_receipt(&wallet, &hash, 50).await;

//     let tx = wallet.get_transaction_by_hash(hash).await.unwrap().unwrap();
//     assert_eq!(tx.as_recovered().chain_id(), None);
//     assert_eq!(tx.as_recovered().tx_type(), TxType::Legacy);

//     let balance = wallet.get_balance(to).await.unwrap().to::<u128>();
//     assert_eq!(balance, 123);
// }

sol!(
    #[sol(rpc)]
    "tests/it/contracts/SetGetContractValue.sol"
);
#[zilliqa_macros::test]
async fn eth_call(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (address, _hash) = deploy_contract(
        "tests/it/contracts/SetGetContractValue.sol",
        "SetGetContractValue",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let abi = SetGetContractValue::new(address, &wallet);
    let value = abi.getUint256().call().await.unwrap();
    assert_eq!(value, U256::from(99));
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/RevertMe.sol"
);
#[zilliqa_macros::test]
async fn revert_transaction(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (address, _hash) = deploy_contract(
        "tests/it/contracts/RevertMe.sol",
        "RevertMe",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let revertme = RevertMe::new(address, &wallet);

    // First ensure contract works
    let hash = *revertme.revertable(true).send().await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;
    assert!(receipt.status());

    // Ensure value was incremented
    let value = revertme.value().call().await.unwrap();
    assert_eq!(value, I256::unchecked_from(1));

    // Next ensure revert fails correctly
    let hash = *revertme
        .revertable(false)
        .gas(1_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;
    assert!(!receipt.status());

    // Ensure value was NOT incremented a second time
    let value = revertme.value().call().await.unwrap();
    assert_eq!(value, I256::unchecked_from(1));
}

#[zilliqa_macros::test]
async fn gas_charged_on_revert(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (contract_address, _) = deploy_contract(
        "tests/it/contracts/RevertMe.sol",
        "RevertMe",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = RevertMe::new(contract_address, &wallet);

    let gas_price = wallet.get_gas_price().await.unwrap();

    // Revert on contract failure. Ensure gas is consumed according to execution.
    let balance_before_call = wallet
        .get_balance(wallet.default_signer_address())
        .await
        .unwrap()
        .to::<u128>();
    let large_gas_limit = 1_000_000;
    let hash = *contract
        .revertable(false)
        .gas(large_gas_limit)
        .send()
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;

    assert!(!receipt.status());
    assert!(receipt.gas_used > 0);
    assert!(receipt.gas_used < large_gas_limit);

    let balance_after_call = wallet
        .get_balance(wallet.default_signer_address())
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(
        balance_after_call,
        balance_before_call - gas_price * receipt.gas_used as u128
    );

    // Revert on out-of-gas. Ensure entire gas limit is consumed.
    let balance_before_call = wallet
        .get_balance(wallet.default_signer_address())
        .await
        .unwrap()
        .to::<u128>();

    // Set the gas limit of this transaction to be half of the previous successful call. This guarantees we will fail
    // due to running out of gas.
    let small_gas_limit = receipt.gas_used / 2;
    let hash = *contract
        .revertable(true)
        .gas(small_gas_limit)
        .send()
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;

    assert!(!receipt.status());
    let balance_after_call = wallet
        .get_balance(wallet.default_signer_address())
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(
        balance_after_call,
        balance_before_call - gas_price * small_gas_limit as u128
    );
}

#[zilliqa_macros::test]
async fn nonces_rejected_too_high(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let to = Address::random();
    // Tx nonce of 1 should never get mined
    let tx = TransactionRequest::default()
        .to(to)
        .value(U256::from(100))
        .nonce(1);

    let hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();
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
    let to = Address::random();

    let mut txs_to_send: Vec<TransactionRequest> = Vec::new();
    let tx_send_amount = 10;
    let tx_send_iterations = 100;

    // collect up a bunch of TXs to send at once, but in reverse order
    for i in (0..tx_send_iterations).rev() {
        let tx = TransactionRequest::default()
            .to(to)
            .value(U256::from(tx_send_amount))
            .nonce(i);
        txs_to_send.push(tx);
    }

    // collect the promises and await on them
    let mut promises = Vec::new();

    // Send all of them
    for tx in txs_to_send {
        let prom = wallet.send_transaction(tx);
        promises.push(prom);
    }

    // Wait for all of them to be completed
    join_all(promises).await;

    // Wait until target account has got all the TXs
    let wait = network
        .run_until_async(
            || async {
                wallet.get_balance(to).await.unwrap() == (tx_send_amount * tx_send_iterations)
            },
            10000,
        )
        .await;

    // doesn't time out trying to mine
    assert!(wait.is_ok());
}

#[zilliqa_macros::test]
async fn priority_fees_tx(mut network: Network) {
    let gas_price = network.get_node(0).get_gas_price();
    let wallet = network.genesis_wallet().await;

    let to = Address::random();

    let mut txs_to_send: Vec<TransactionRequest> = Vec::new();
    let tx_send_amount = 10;
    let tx_send_iterations = 10;

    // collect up a bunch of TXs to send at once, with two per nonce (one with a priority fee)
    // but starting from nonce 1 to allow the mempool time to see them all without being able to mine them yet
    for i in 1..tx_send_iterations {
        // Lo priority tx should never get mined
        let tx = TransactionRequest::default()
            .to(to)
            .value(U256::from(1))
            .gas_price(gas_price)
            .nonce(i);
        txs_to_send.push(tx);

        // Hi priority tx
        let tx = TransactionRequest::default()
            .to(to)
            .value(U256::from(tx_send_amount))
            .nonce(i)
            .gas_price(gas_price * 2);
        txs_to_send.push(tx);
    }

    // collect the promises and await on them
    let mut promises = Vec::new();
    let txns_count = txs_to_send.len();
    // Send all of them
    for tx in txs_to_send {
        let prom = wallet.send_transaction(tx);
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
    let tx = TransactionRequest::default()
        .to(to)
        .nonce(0)
        .value(U256::from(tx_send_amount));
    let _ = wallet.send_transaction(tx).await.unwrap();

    // Wait until target account has got all the TXs
    let wait = network
        .run_until_async(
            || async {
                wallet.get_balance(to).await.unwrap() == (tx_send_amount * tx_send_iterations)
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
    // let client = wallet.client();

    // Send a transaction.
    let hash = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(Address::random())
                .value(U256::from(10)),
        )
        .await
        .unwrap()
        .tx_hash();

    // Check the transaction is returned with null values for the block.
    let tx = wallet.get_transaction_by_hash(hash).await.unwrap().unwrap();
    assert_eq!(tx.block_hash, None);
    assert_eq!(tx.block_number, None);

    // Wait for the transaction to be mined.
    let _ = network.run_until_receipt(&wallet, &hash, 100).await;

    // Check the transaction is returned with non-null values for the block.
    let tx = wallet.get_transaction_by_hash(hash).await.unwrap().unwrap();
    assert!(tx.block_hash.is_some());
    assert!(tx.block_number.is_some());
}

#[zilliqa_macros::test]
async fn get_transaction_by_index(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Send transaction in reverse nonce order to ensure they land in the same block
    let h1 = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(Address::random())
                .value(U256::from(10))
                .nonce(1),
        )
        .await
        .unwrap()
        .tx_hash();

    let h2 = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(Address::random())
                .value(U256::from(10))
                .nonce(0),
        )
        .await
        .unwrap()
        .tx_hash();

    let r1 = network.run_until_receipt(&wallet, &h1, 50).await;
    let r2 = network.run_until_receipt(&wallet, &h2, 50).await;

    // NOTE: they are not always in the same block
    if r1.block_hash == r2.block_hash {
        let block_hash = r1.block_hash.unwrap();
        let block_number = r1.block_number.unwrap();

        let txn = wallet
            .get_transaction_by_block_hash_and_index(block_hash, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.info().hash.unwrap(), h2);

        let txn = wallet
            .get_transaction_by_block_number_and_index(BlockNumberOrTag::Number(block_number), 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.info().hash.unwrap(), h1);
    } else {
        let block_hash = r2.block_hash.unwrap();
        let block_number = r1.block_number.unwrap();

        let txn = wallet
            .get_transaction_by_block_hash_and_index(block_hash, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.info().hash.unwrap(), h2);

        let txn = wallet
            .get_transaction_by_block_number_and_index(BlockNumberOrTag::Number(block_number), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(txn.info().hash.unwrap(), h1);
    }
}

#[zilliqa_macros::test]
async fn block_subscription(mut network: Network) {
    let wallet = network.genesis_pubsub_wallet().await;

    let subs = wallet.subscribe_blocks().await.unwrap();
    network.run_until_block_finalized(4, 100).await.unwrap();

    // let _sub_id = *subs.local_id();
    let mut block_stream = subs.into_stream();

    // Assert the stream contains next 2 blocks; usually (3,4) or (4,5)
    let a = block_stream.next().await.unwrap().number;
    let b = block_stream.next().await.unwrap().number;
    assert!(a + 1 == b);
    assert!(a <= 4);
    assert!(b <= 5);

    // FIXME: eth_unsubscribe
    // let _ = wallet.unsubscribe(sub_id).await.unwrap();
}

#[zilliqa_macros::test]
async fn logs_subscription(mut network: Network) {
    let wallet = network.genesis_pubsub_wallet().await;

    let (contract_address, _receipt) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;
    let contract = EmitEvents::new(contract_address, &wallet);

    // Our filtering logic is tested above by the `eth_getLogs` test, so in this test we just check whether logs are
    // returned at all from the subscription.
    let mut log_stream = wallet
        .subscribe_logs(&Filter::new())
        .await
        .unwrap()
        .into_stream();

    let hash = *contract.emitEvents().send().await.unwrap().tx_hash();
    network.run_until_receipt(&wallet, &hash, 50).await;

    assert_eq!(log_stream.next().await.unwrap().address(), contract_address);
    assert_eq!(log_stream.next().await.unwrap().address(), contract_address);

    // assert!(log_stream.unsubscribe().await.unwrap());
}

#[zilliqa_macros::test]
async fn new_transaction_subscription(mut network: Network) {
    let wallet = network.genesis_pubsub_wallet().await;

    let mut txn_stream = wallet
        .subscribe_full_pending_transactions()
        .await
        .unwrap()
        .into_stream();
    let mut hash_stream = wallet
        .subscribe_pending_transactions()
        .await
        .unwrap()
        .into_stream();

    let txn = TransactionRequest::default()
        .to(Address::random())
        .value(U256::from(10));
    let txn_hash = *wallet.send_transaction(txn).await.unwrap().tx_hash();

    // Note we don't wait for the transaction to be mined - The subscriptions should already contain this transaction.

    assert_eq!(
        txn_stream.next().await.unwrap().info().hash.unwrap(),
        txn_hash
    );
    assert_eq!(hash_stream.next().await.unwrap(), txn_hash);

    // assert!(txn_stream.unsubscribe().await.unwrap());
    // assert!(hash_stream.unsubscribe().await.unwrap());
}

#[zilliqa_macros::test]
async fn get_accounts_with_nonexistent_params(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    // Attempt to call eth_accounts (as a random example) with no parameters at all and check that the
    // call succeeds and the result is empty.
    let result = wallet
        .client()
        .request_noparams::<Vec<Address>>("eth_accounts")
        .await
        .unwrap();

    assert!(result.is_empty());
}

#[zilliqa_macros::test]
async fn get_accounts_with_extra_args(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    // Attempt to call eth_accounts (as a random example) with no parameters at all and check that the
    // call succeeds and the result is empty.
    let result = wallet
        .client()
        .request::<Vec<&str>, Vec<Address>>("eth_accounts", vec!["extra"])
        .await;

    assert!(result.is_err());
}

// FIXME:
// #[zilliqa_macros::test]
// async fn deploy_deterministic_deployment_proxy(mut network: Network) {
//     let wallet = network.genesis_wallet().await;

//     let signer = Address::random();

//     let gas_price = 100000000000u128;
//     let gas = 100000u64;

//     // Send the signer enough money to cover the deployment.
//     let tx = TransactionRequest::default()
//         .to(signer)
//         .value(U256::from(gas_price * gas as u128));
//     let hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();

//     // Transaction from https://github.com/Arachnid/deterministic-deployment-proxy.
//     let tx = TransactionRequest::default()
//         .nonce(0)
//         .gas_price(gas_price)
//         .gas_limit(gas)
//         .value(U256::ZERO)
//         .input(TransactionInput::both(hex!("604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3").into()));

//     let tx = tx.build_legacy().unwrap();
//     // let signature = Signature {
//     //     r: hex!("2222222222222222222222222222222222222222222222222222222222222222").into(),
//     //     s: hex!("2222222222222222222222222222222222222222222222222222222222222222").into(),
//     //     v: 27,
//     // };
//     // let raw_tx = tx.rlp_signed(&signature);
//     let hash = wallet.send_raw_transaction(raw_tx).await.unwrap().tx_hash();

//     let receipt = network.run_until_receipt(&wallet, hash, 150).await;

//     assert_eq!(receipt.from, signer);
//     assert_eq!(
//         receipt.contract_address.unwrap(),
//         "0x4e59b44847b379578588920ca78fbf26c0b4956c"
//             .parse()
//             .unwrap()
//     );
// }

#[zilliqa_macros::test]
async fn test_send_transaction_errors(mut network: Network) {
    let wallet = network.random_wallet().await;

    async fn send_transaction_get_error(wallet: &Wallet, tx: TransactionRequest) -> (i64, String) {
        let result = wallet.send_transaction(tx).await;
        assert!(result.is_err());
        let val = result.unwrap_err();
        let err = val.as_error_resp().unwrap();
        (err.code, err.message.to_string())
    }
    async fn _send_raw_transaction_get_error(wallet: &Wallet, tx: Bytes) -> (i64, String) {
        let result = wallet.send_raw_transaction(&tx).await;
        assert!(result.is_err());
        let val = result.unwrap_err();
        let err = val.as_error_resp().unwrap();
        (err.code, err.message.to_string())
    }

    let gas_price = 100000000000u128;
    let gas = 100000u128;

    // Give the signer some funds.
    let tx = TransactionRequest::default()
        .to(wallet.default_signer_address())
        .value(U256::from(2 * gas_price * gas));
    let genesis_wallet = network.genesis_wallet().await;
    let hash = *genesis_wallet.send_transaction(tx).await.unwrap().tx_hash();
    let _receipt = network.run_until_receipt(&wallet, &hash, 50).await;

    // Deliberately set too low a gas fee
    {
        let tx = TransactionRequest::default()
            .to(Address::random())
            .value(U256::from(10))
            .gas_limit(1);
        let (code, msg) = send_transaction_get_error(&wallet, tx).await;
        assert_eq!(code, -32602);
        assert!(msg.to_lowercase().contains("gas"));
    }
    // FIXME: Test sending a corrupt transaction
    // {
    //     let tx = TransactionRequest::default()
    //         .to(Address::random())
    //         .value(U256::from(gas_price * gas))
    //         .gas_limit(gas as u64);

    //     // let tx_env = tx.build(&wallet.wallet()).await.unwrap();
    //     let signed = wallet.sign_transaction(tx).await.unwrap();
    //     let (code, _) = send_raw_transaction_get_error(&wallet, signed).await;
    //     assert_eq!(code, -32603);
    // }
    // it would be nice to test bad signatures, but generating one without
    // causing other spurious errors appears to be hard.
    {
        let tx = TransactionRequest::default()
            .to(Address::random())
            .value(U256::from(200 * gas_price * gas))
            .nonce(547);
        let (code, msg) = send_transaction_get_error(&wallet, tx).await;
        assert_eq!(code, -32602);
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
    let wallet = network.random_wallet().await;

    let result = wallet
        .client()
        .request_noparams::<SyncingResult>("eth_syncing")
        .await
        .unwrap();
    assert_eq!(result, SyncingResult::Bool(false))
}

#[zilliqa_macros::test]
async fn get_block_receipts(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Deploy a contract to generate a transaction
    let (_, receipt1) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let block_hash = receipt1.block_hash.unwrap();

    // Get receipts by block hash
    let receipts: Vec<TransactionReceipt> = wallet
        .client()
        .request("eth_getBlockReceipts", [block_hash])
        .await
        .unwrap();

    assert_eq!(receipts.len(), 1);
    assert!(
        receipts
            .iter()
            .any(|r| r.transaction_hash == receipt1.transaction_hash)
    );

    // Verify receipts match individual receipt queries
    let individual1 = wallet
        .get_transaction_receipt(receipt1.transaction_hash)
        .await
        .unwrap()
        .unwrap();

    assert!(receipts.contains(&individual1));
}

#[zilliqa_macros::test]
async fn test_block_filter(mut network: Network) {
    println!("Starting block filter test");
    let wallet = network.random_wallet().await;

    // Create a new block filter
    println!("Creating new block filter");
    let filter_id = wallet
        .client()
        .request_noparams::<u128>("eth_newBlockFilter")
        .await
        .unwrap();
    println!("Created filter with ID: {filter_id}");

    // Generate some blocks
    println!("Generating blocks");
    network.run_until_block_finalized(4, 500).await.unwrap();
    println!("Generated blocks");

    // Get filter changes - should return the new block hashes
    println!("Getting filter changes");
    let changes_result = wallet
        .client()
        .request::<_, Value>("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<TxHash> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes", changes.len());

    // We should have at least 2 new blocks (not counting the block at which we created the filter)
    assert!(!changes.is_empty());
    assert!(changes.len() >= 2);

    // Changes should be valid block hashes
    println!("Verifying block hashes");
    for hash in &changes {
        println!("Checking block hash: {hash}");
        let _ = wallet
            .get_block_by_hash(*hash)
            .await
            .unwrap()
            .unwrap()
            .number();
    }

    // Calling get_filter_changes again should return empty as we've already retrieved the changes
    println!("Getting filter changes second time");
    let changes_result = wallet
        .client()
        .request::<_, Value>("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<TxHash> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes on second call", changes.len());
    dbg!(&changes);
    assert!(changes.is_empty());

    println!("Removing filter");
    let filter_removed_successfully = wallet
        .client()
        .request::<_, bool>("eth_uninstallFilter", [filter_id])
        .await
        .unwrap();
    println!("Filter removed: {filter_removed_successfully}");
    assert!(filter_removed_successfully);
}

#[zilliqa_macros::test]
async fn test_pending_transaction_filter(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create a new pending transaction filter
    println!("Creating new pending transaction filter");
    let filter_id = wallet
        .client()
        .request_noparams::<u128>("eth_newPendingTransactionFilter")
        .await
        .unwrap();
    println!("Created filter with ID: {filter_id}");

    // Send a transaction.
    let hash = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(Address::random())
                .value(U256::from(10)),
        )
        .await
        .unwrap()
        .tx_hash();

    // Get filter changes - should return the pending transaction hashes
    println!("Getting filter changes");
    let changes_result = wallet
        .client()
        .request::<_, Value>("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<TxHash> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes", changes.len());

    assert!(changes.contains(&hash));

    // Calling get_filter_changes again should return empty
    println!("Getting filter changes second time");
    let changes_result: serde_json::Value = wallet
        .client()
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<TxHash> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes on second call", changes.len());
    assert!(changes.is_empty());
}

#[zilliqa_macros::test]
async fn test_log_filter(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (contract_address, _) = deploy_contract(
        "tests/it/contracts/EmitEvents.sol",
        "EmitEvents",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = EmitEvents::new(contract_address, &wallet);

    // Create a filter for contract events
    println!("Creating event filter");
    let filter = json!({
        "fromBlock": "latest",
        "address": contract_address,
    });
    let filter_id = wallet
        .client()
        .request::<_, u128>("eth_newFilter", [filter])
        .await
        .unwrap();
    println!("Created filter with ID: {filter_id}");

    let hash = *contract.emitEvents().send().await.unwrap().tx_hash();
    network.run_until_receipt(&wallet, &hash, 50).await;

    // Get filter changes
    println!("Getting filter changes");
    let logs_result = wallet
        .client()
        .request::<_, Value>("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    dbg!(&logs_result);
    let logs: Vec<serde_json::Value> = serde_json::from_value(logs_result).unwrap();
    println!("Got {} logs", logs.len());

    assert_eq!(logs.len(), 2);

    // Test get_filter_logs
    println!("Testing get_filter_logs");
    let logs_via_get_result = wallet
        .client()
        .request::<_, Value>("eth_getFilterLogs", [filter_id])
        .await
        .unwrap();
    let logs_via_get: Vec<serde_json::Value> = serde_json::from_value(logs_via_get_result).unwrap();
    assert_eq!(logs, logs_via_get);

    // Calling get_filter_changes again should return empty
    println!("Getting filter changes second time");
    let changes_result = wallet
        .client()
        .request::<_, Value>("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    let changes: Vec<serde_json::Value> = serde_json::from_value(changes_result).unwrap();
    println!("Got {} changes on second call", changes.len());
    assert!(changes.is_empty());

    println!("Removing filter");
    let filter_removed_successfully = wallet
        .client()
        .request::<_, bool>("eth_uninstallFilter", [filter_id])
        .await
        .unwrap();
    println!("Filter removed: {filter_removed_successfully}");
    assert!(filter_removed_successfully);
}

#[zilliqa_macros::test]
async fn test_invalid_filter_id(mut network: Network) {
    println!("Starting invalid filter ID test");
    let wallet = network.random_wallet().await;

    // Try to get changes for non-existent filter
    println!("Attempting to get changes for invalid filter ID");
    let result = wallet
        .client()
        .request::<_, Value>("eth_getFilterChanges", ["0x123"])
        .await;
    assert!(result.is_err());
}

#[zilliqa_macros::test]
async fn test_uninstall_filter(mut network: Network) {
    println!("Starting uninstall filter test");
    let wallet = network.random_wallet().await;

    // Create a new filter
    println!("Creating new block filter");
    let filter_id = wallet
        .client()
        .request_noparams::<u128>("eth_newBlockFilter")
        .await
        .unwrap();
    println!("Created filter with ID: {filter_id}");

    // Verify filter exists by using it
    println!("Verifying filter exists");
    let _changes: Vec<TxHash> = wallet
        .client()
        .request("eth_getFilterChanges", [filter_id])
        .await
        .unwrap();
    println!("Filter verified");

    // Successfully uninstall the filter
    println!("Uninstalling filter");
    let filter_removed = wallet
        .client()
        .request::<_, bool>("eth_uninstallFilter", [filter_id])
        .await
        .unwrap();
    println!("Filter removed: {filter_removed}");
    assert!(filter_removed);

    // Verify filter no longer exists
    println!("Verifying filter no longer exists");
    let result = wallet
        .client()
        .request::<_, Value>("eth_getFilterChanges", [filter_id])
        .await;
    assert!(result.is_err());
}

#[zilliqa_macros::test]
async fn get_block_by_number(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Get the latest block number
    let latest_number = wallet.get_block_number().await.unwrap();

    // Query eth_getBlockByNumber with 'latest', full transactions requested
    let block = wallet
        .client()
        .request::<_, serde_json::Value>("eth_getBlockByNumber", (latest_number.to_hex(), true))
        .await
        .unwrap();

    // Some block fields should always be present
    assert_eq!(
        block["number"],
        serde_json::json!(format!("0x{:x}", latest_number))
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

sol!(
    #[sol(rpc)]
    "tests/it/contracts/BytesArray.sol"
);
#[zilliqa_macros::test]
async fn read_byte_array_length(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (addr, _hash) = deploy_contract(
        "tests/it/contracts/BytesArray.sol",
        "BytesArrayContract",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = BytesArrayContract::new(addr, &wallet);
    // Query the current block number with an `eth_call`.
    let length = contract.getLength().call().await.unwrap();

    assert_eq!(length, U256::ZERO);
}
