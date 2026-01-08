use std::str::FromStr;

use alloy::{
    eips::BlockId,
    primitives::{Address, BlockHash, TxHash, U64, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
    sol,
};
use futures::future::join_all;
use itertools::Itertools;
use serde_json::{Value, json};
use zilliqa::api::to_hex::ToHex;

use crate::{Network, Wallet, deploy_contract};

async fn search_transactions(
    wallet: &Wallet,
    address: &Address,
    block_number: u64,
    page_size: usize,
    reverse: bool,
) -> Value {
    let method = if reverse {
        "ots_searchTransactionsBefore"
    } else {
        "ots_searchTransactionsAfter"
    };
    let result = wallet
        .client()
        .request(
            method,
            [
                json!(address.to_hex()),
                json!(block_number),
                json!(page_size),
            ],
        )
        .await
        .unwrap();
    tracing::debug!("{result:?}");
    result
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/CallingContract.sol"
);

#[zilliqa_macros::test]
async fn search_transactions_evm(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (caller_address, _) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Caller",
        0,
        &wallet,
        &mut network,
    )
    .await;
    let caller_abi = Caller::new(caller_address, &wallet);

    let (callee_address, _) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Callee",
        0,
        &wallet,
        &mut network,
    )
    .await;

    let n = wallet.get_block_number().await.unwrap();

    let call_hash = *caller_abi
        .setX(callee_address, U256::from(0xDEADBEEFu32))
        .send()
        .await
        .unwrap()
        .tx_hash();
    let _receipt = network.run_until_receipt(&wallet, &call_hash, 100).await;

    // Search for the transaction with: the sender, the caller contract and the callee contract.
    let wallet_tx =
        search_transactions(&wallet, &wallet.default_signer_address(), n, 1, false).await;
    assert_eq!(wallet_tx["txs"].as_array().unwrap().len(), 1);
    let caller_tx = search_transactions(&wallet, &caller_address, n, 1, false).await;
    assert_eq!(caller_tx["txs"].as_array().unwrap().len(), 1);
    let callee_tx = search_transactions(&wallet, &callee_address, n, 1, false).await;
    assert_eq!(callee_tx["txs"].as_array().unwrap().len(), 1);

    // Ensure that they are all the same block
    assert_eq!(
        wallet_tx["txs"][0]["blockHash"],
        caller_tx["txs"][0]["blockHash"]
    );
    assert_eq!(
        wallet_tx["txs"][0]["blockHash"],
        callee_tx["txs"][0]["blockHash"]
    );
}

// TODO: Add test for searching for internal Scilla contract calls once they are supported.

#[zilliqa_macros::test]
async fn search_transactions_paging(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Generate 16 transactions.
    let to = Address::random();
    let hashes: Vec<_> = join_all((0..16).map(|i| {
        let wallet = &wallet;
        async move {
            let tx = TransactionRequest::default()
                .to(to)
                .value(U256::from(123))
                .nonce(i);
            *wallet.send_transaction(tx).await.unwrap().tx_hash()
        }
    }))
    .await;

    for h in hashes {
        network.run_until_receipt(&wallet, &h, 100).await;
    }

    let page_size = 8;
    let response = search_transactions(
        &wallet,
        &wallet.default_signer_address(),
        0,
        page_size,
        false,
    )
    .await;
    let txs = response["txs"].as_array().unwrap();
    // Response should include at least as many transactions as the page size.
    assert!(txs.len() >= page_size);
    // It should include all transactions from the last block (even if this results in more txs than `page_size`).
    let last_block_hash = txs[txs.len() - 1]["blockHash"].as_str().unwrap();
    let last_block = wallet
        .get_block(BlockId::hash(BlockHash::from_str(last_block_hash).unwrap()))
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

    let response =
        search_transactions(&wallet, &wallet.default_signer_address(), 0, 16, false).await;
    let txs = response["txs"].as_array().unwrap();
    // It should be marked as the first (latest) page because we queried for all 16 transactions.
    assert!(response["firstPage"].as_bool().unwrap());
    // Transactions should be returned in descending order (latest to earliest)
    assert!(
        txs.iter()
            .map(|tx| (
                tx["blockNumber"].as_str().unwrap().parse::<U64>().unwrap(),
                tx["transactionIndex"]
                    .as_str()
                    .unwrap()
                    .parse::<U64>()
                    .unwrap(),
            ))
            .tuple_windows()
            .all(|(a, b)| a > b)
    );

    let response = search_transactions(&wallet, &wallet.default_signer_address(), 0, 1, true).await;
    let txs = response["txs"].as_array().unwrap();
    // Searching in reverse from the latest block and a page size of 1 should only yield results from a single block.
    assert!(!txs.is_empty());
    assert!(
        txs.iter()
            .map(|tx| tx["blockHash"].as_str().unwrap())
            .all_equal()
    );
    // Transactions should be returned in descending order (latest to earliest)
    assert!(
        txs.iter()
            .map(|tx| (
                tx["blockNumber"].as_str().unwrap().parse::<U64>().unwrap(),
                tx["transactionIndex"]
                    .as_str()
                    .unwrap()
                    .parse::<U64>()
                    .unwrap(),
            ))
            .tuple_windows()
            .all(|(a, b)| a > b)
    );
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/ContractCreatesAnotherContract.sol"
);
#[zilliqa_macros::test]
async fn contract_creator(mut network: Network) {
    async fn get_contract_creator(wallet: &Wallet, address: Address) -> Option<(TxHash, Address)> {
        let response: Value = wallet
            .client()
            .request("ots_getContractCreator", [json!(address.to_hex())])
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
    assert_eq!(
        get_contract_creator(&wallet, wallet.default_signer_address()).await,
        None
    );

    let (creator_address, creator_receipt) = deploy_contract(
        "tests/it/contracts/ContractCreatesAnotherContract.sol",
        "Creator",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    // The EOA is the creator of the `Creator` contract.
    assert_eq!(
        get_contract_creator(&wallet, creator_address).await,
        Some((
            creator_receipt.transaction_hash,
            wallet.default_signer_address()
        ))
    );

    let creator = Creator::new(creator_address, &wallet);
    let hash = *creator.create().send().await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 50).await;

    // Extract the value from the `Created` event.
    let log = receipt.decoded_log::<Creator::Created>().unwrap();
    let Creator::Created { createMe } = log.data;
    // The `Creator` is the creator of the `CreateMe` contract.
    assert_eq!(
        get_contract_creator(&wallet, createMe).await,
        Some((hash, creator_address))
    );

    // TODO: Test Scilla contract
}

#[zilliqa_macros::test]
async fn trace_transaction(mut network: Network) {
    async fn get_trace(wallet: &Wallet, hash: TxHash) -> Value {
        wallet
            .client()
            .request("ots_traceTransaction", [json!(hash.to_hex())])
            .await
            .unwrap()
    }

    let wallet = network.genesis_wallet().await;

    let (caller_address, receipt) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Caller",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let trace = get_trace(&wallet, receipt.transaction_hash).await;
    assert_eq!(trace.as_array().unwrap().len(), 1);

    let entry = &trace[0];
    assert_eq!(entry["type"], "CREATE");
    assert_eq!(entry["depth"], 0);
    assert_eq!(
        entry["from"].as_str().unwrap().parse::<Address>().unwrap(),
        wallet.default_signer_address()
    );
    assert_eq!(
        entry["to"].as_str().unwrap().parse::<Address>().unwrap(),
        caller_address
    );

    let (callee_address, _hash) = deploy_contract(
        "tests/it/contracts/CallingContract.sol",
        "Callee",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let caller_abi = Caller::new(caller_address, &wallet);
    let hash = *caller_abi
        .setX(callee_address, U256::from(0x517710Au32))
        .send()
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, &hash, 100).await;

    let trace = get_trace(&wallet, hash).await;
    assert_eq!(trace.as_array().unwrap().len(), 2);
    let first = &trace[0];
    let second = &trace[1];
    assert_eq!(first["type"], "CALL");
    assert_eq!(first["depth"], 0);
    assert_eq!(
        first["to"].as_str().unwrap().parse::<Address>().unwrap(),
        caller_address
    );
    assert_eq!(second["type"], "CALL");
    assert_eq!(second["depth"], 1);
    assert_eq!(
        second["to"].as_str().unwrap().parse::<Address>().unwrap(),
        callee_address
    );

    // TODO: Test Scilla contract
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/RevertMe.sol"
);
#[zilliqa_macros::test]
async fn get_transaction_error(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (address, _) = deploy_contract(
        "tests/it/contracts/RevertMe.sol",
        "RevertMe",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = RevertMe::new(address, &wallet);

    let hash = *contract
        .revertable(false)
        .gas(1_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, &hash, 50).await;

    let error: String = wallet
        .client()
        .request("ots_getTransactionError", [json!(hash.to_hex())])
        .await
        .unwrap();

    let error = error.strip_prefix("0x").unwrap();
    let error = hex::decode(error).unwrap();
    let error = alloy::sol_types::decode_revert_reason(&error).unwrap();
    assert!(error.ends_with("Reverting."));

    // TODO: Test Scilla contract
}
