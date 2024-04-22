use std::{ops::DerefMut, str::FromStr};

use ethabi::Token;
use ethers::{
    providers::Middleware,
    types::{TransactionRequest, U64},
    utils,
};
use futures::future::join_all;
use itertools::Itertools;
use primitive_types::{H160, H256};
use serde_json::Value;

use crate::{deploy_contract, Network, Wallet};

async fn search_transactions(
    wallet: &Wallet,
    address: H160,
    block_number: u64,
    page_size: usize,
    reverse: bool,
) -> Value {
    let method = if reverse {
        "ots_searchTransactionsBefore"
    } else {
        "ots_searchTransactionsAfter"
    };
    wallet
        .provider()
        .request(
            method,
            [
                utils::serialize(&address),
                utils::serialize(&block_number),
                utils::serialize(&page_size),
            ],
        )
        .await
        .unwrap()
}

#[zilliqa_macros::test]
async fn search_transactions_evm(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (hash, caller_abi) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Caller",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let caller_address = receipt.contract_address.unwrap();

    let (hash, _) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Callee",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let callee_address = receipt.contract_address.unwrap();

    let data = caller_abi
        .function("setX")
        .unwrap()
        .encode_input(&[Token::Address(callee_address), Token::Uint(123.into())])
        .unwrap();

    let tx = TransactionRequest::new().to(caller_address).data(data);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    network.run_until_receipt(&wallet, hash, 50).await;

    // Search for the transaction with: the sender, the caller contract and the callee contract.
    let response = search_transactions(&wallet, wallet.address(), 0, 1, false).await;
    assert_eq!(response["txs"].as_array().unwrap().len(), 1);
    let response = search_transactions(&wallet, caller_address, 0, 1, false).await;
    assert_eq!(response["txs"].as_array().unwrap().len(), 1);
    let response = search_transactions(&wallet, callee_address, 0, 1, false).await;
    assert_eq!(response["txs"].as_array().unwrap().len(), 1);
}

// TODO: Add test for searching for internal Scilla contract calls once they are supported.

#[zilliqa_macros::test]
async fn search_transactions_paging(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Generate 16 transactions.
    let to = H160::random_using(network.rng.lock().unwrap().deref_mut());
    let hashes: Vec<_> = join_all((0..16).map(|i| {
        let wallet = &wallet;
        async move {
            let tx = TransactionRequest::pay(to, 123).nonce(i);
            wallet.send_transaction(tx, None).await.unwrap().tx_hash()
        }
    }))
    .await;

    for h in hashes {
        network.run_until_receipt(&wallet, h, 50).await;
    }

    let page_size = 8;
    let response = search_transactions(&wallet, wallet.address(), 0, page_size, false).await;
    let txs = response["txs"].as_array().unwrap();
    // Response should include at least as many transactions as the page size.
    assert!(txs.len() >= page_size);
    // It should include all transactions from the last block (even if this results in more txs than `page_size`).
    let last_block_hash = txs[txs.len() - 1]["blockHash"].as_str().unwrap();
    let last_block = wallet
        .get_block(H256::from_str(last_block_hash).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        txs.iter()
            .filter(|tx| tx["blockHash"] == last_block_hash)
            .count(),
        last_block.transactions.len()
    );
    // It should be marked as the last (earliest) page because we started from the genesis block.
    assert!(response["lastPage"].as_bool().unwrap());

    let response = search_transactions(&wallet, wallet.address(), 0, 16, false).await;
    let txs = response["txs"].as_array().unwrap();
    // It should be marked as the first (latest) page because we queried for all 16 transactions.
    assert!(response["firstPage"].as_bool().unwrap());
    // Transactions should be returned in descending order (latest to earliest)
    assert!(txs
        .iter()
        .map(|tx| (
            tx["blockNumber"].as_str().unwrap().parse::<U64>().unwrap(),
            tx["transactionIndex"]
                .as_str()
                .unwrap()
                .parse::<U64>()
                .unwrap(),
        ))
        .tuple_windows()
        .all(|(a, b)| a > b));

    let response = search_transactions(&wallet, wallet.address(), 0, 1, true).await;
    let txs = response["txs"].as_array().unwrap();
    // Searching in reverse from the latest block and a page size of 1 should only yield results from a single block.
    assert!(!txs.is_empty());
    assert!(txs
        .iter()
        .map(|tx| tx["blockHash"].as_str().unwrap())
        .all_equal());
    // Transactions should be returned in descending order (latest to earliest)
    assert!(txs
        .iter()
        .map(|tx| (
            tx["blockNumber"].as_str().unwrap().parse::<U64>().unwrap(),
            tx["transactionIndex"]
                .as_str()
                .unwrap()
                .parse::<U64>()
                .unwrap(),
        ))
        .tuple_windows()
        .all(|(a, b)| a > b));
}

#[zilliqa_macros::test]
async fn contract_creator(mut network: Network) {
    async fn get_contract_creator(wallet: &Wallet, address: H160) -> Option<(H256, H160)> {
        let response: Value = wallet
            .provider()
            .request("ots_getContractCreator", [address])
            .await
            .unwrap();

        if response.is_null() {
            None
        } else {
            Some((
                response["hash"].as_str().unwrap().parse().unwrap(),
                response["creator"].as_str().unwrap().parse().unwrap(),
            ))
        }
    }

    let wallet = network.genesis_wallet().await;

    // EOAs have no creator
    assert_eq!(get_contract_creator(&wallet, wallet.address()).await, None);

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/ContractCreatesAnotherContract.sol",
        "Creator",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let creator_address = receipt.contract_address.unwrap();

    // The EOA is the creator of the `Creator` contract.
    assert_eq!(
        get_contract_creator(&wallet, creator_address).await,
        Some((hash, wallet.address()))
    );

    let data = abi.function("create").unwrap().encode_input(&[]).unwrap();

    let tx = TransactionRequest::new().to(creator_address).data(data);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, hash, 50).await;
    let log = abi
        .event("Created")
        .unwrap()
        .parse_log_whole(receipt.logs[0].clone().into())
        .unwrap();
    let create_me_address = log.params[0].value.clone().into_address().unwrap();

    // The `Creator` is the creator of the `CreateMe` contract.
    assert_eq!(
        get_contract_creator(&wallet, create_me_address).await,
        Some((hash, creator_address))
    );

    // TODO: Test Scilla contract
}

#[zilliqa_macros::test]
async fn trace_transaction(mut network: Network) {
    async fn get_trace(wallet: &Wallet, hash: H256) -> Value {
        wallet
            .provider()
            .request("ots_traceTransaction", [hash])
            .await
            .unwrap()
    }

    let wallet = network.genesis_wallet().await;

    let (hash, caller_abi) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Caller",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let caller_address = receipt.contract_address.unwrap();

    let trace = get_trace(&wallet, hash).await;
    assert_eq!(trace.as_array().unwrap().len(), 1);
    let entry = &trace[0];
    assert_eq!(entry["type"], "CREATE");
    assert_eq!(entry["depth"], 0);
    assert_eq!(
        entry["from"].as_str().unwrap().parse::<H160>().unwrap(),
        wallet.address()
    );
    assert_eq!(
        entry["to"].as_str().unwrap().parse::<H160>().unwrap(),
        caller_address
    );

    let (hash, _) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Callee",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let callee_address = receipt.contract_address.unwrap();

    let data = caller_abi
        .function("setX")
        .unwrap()
        .encode_input(&[Token::Address(callee_address), Token::Uint(123.into())])
        .unwrap();

    let tx = TransactionRequest::new().to(caller_address).data(data);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    network.run_until_receipt(&wallet, hash, 50).await;

    let trace = get_trace(&wallet, hash).await;
    assert_eq!(trace.as_array().unwrap().len(), 2);
    let first = &trace[0];
    let second = &trace[1];
    assert_eq!(first["type"], "CALL");
    assert_eq!(first["depth"], 0);
    assert_eq!(
        first["to"].as_str().unwrap().parse::<H160>().unwrap(),
        caller_address
    );
    assert_eq!(second["type"], "CALL");
    assert_eq!(second["depth"], 1);
    assert_eq!(
        second["to"].as_str().unwrap().parse::<H160>().unwrap(),
        callee_address
    );

    // TODO: Test Scilla contract
}
