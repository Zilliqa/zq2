use std::{fmt::Debug, ops::DerefMut};

use ethabi::{ethereum_types::U64, Token};
use ethers::{
    abi::FunctionExt,
    providers::{Middleware, Provider},
    types::{
        transaction::{
            eip2718::TypedTransaction,
            eip2930::{AccessList, AccessListItem},
        },
        BlockId, BlockNumber, Eip1559TransactionRequest, Eip2930TransactionRequest, Filter,
        Transaction, TransactionReceipt, TransactionRequest,
    },
    utils::keccak256,
};
use futures::future::join_all;
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
    mut tx: TypedTransaction,
) -> (Transaction, TransactionReceipt) {
    let wallet = network.genesis_wallet().await;
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
    let (tx, receipt) = send_transaction(&mut network, tx).await;

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
    let (tx, receipt) = send_transaction(&mut network, tx).await;

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
    let (tx, receipt) = send_transaction(&mut network, tx).await;

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

#[zilliqa_macros::test]
async fn revert_transaction(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/RevertMe.sol",
        "RevertMe",
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
    let (_, receipt) = send_transaction(&mut network, success_call.into()).await;
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
    let (_, receipt) = send_transaction(&mut network, revert_call.into()).await;
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
    let (_, receipt) = send_transaction(&mut network, revert_call.into()).await;

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
    let (_, receipt) = send_transaction(&mut network, fail_out_of_gas_call.into()).await;

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
