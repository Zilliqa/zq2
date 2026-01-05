use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider as _, WalletProvider},
    rpc::types::{TransactionRequest, trace::parity::TraceResults},
};
use serde_json::Value;

use crate::Network;

#[zilliqa_macros::test]
async fn trace_transaction_basic(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create a simple transfer transaction
    let to_addr = Address::random();
    let tx = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(1_000))
        .gas_limit(21_000);

    let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();

    // Wait for transaction to be mined
    network.run_until_receipt(&wallet, &tx_hash, 100).await;

    // Get trace
    let response: Value = wallet
        .client()
        .request("trace_transaction", [tx_hash])
        .await
        .expect("Failed to call trace_transaction API");

    let trace: TraceResults = serde_json::from_value(response).unwrap();
    assert!(!trace.trace.is_empty());
}

#[zilliqa_macros::test]
async fn trace_transaction_not_found(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let nonexistent_hash = B256::random();
    let response: Result<TraceResults, _> = wallet
        .client()
        .request("trace_transaction", [nonexistent_hash])
        .await;

    assert!(response.is_err());
}

#[zilliqa_macros::test]
async fn trace_block_basic(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create some transactions in a block
    let to_addr = Address::random();
    let tx = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(1_000))
        .gas_limit(21_000);

    let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();

    // Wait for block to be mined
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    let block_number = format!("{:#x}", receipt.block_number.unwrap());

    // Get block trace
    let response: Value = wallet
        .client()
        .request("trace_block", [block_number])
        .await
        .expect("Failed to call trace_block API");

    let traces: Vec<TraceResults> = serde_json::from_value(response).unwrap();
    assert!(!traces.is_empty());
}

#[zilliqa_macros::test]
async fn trace_filter_basic(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create transactions from different addresses
    let to_addr = Address::random();
    let tx1 = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(1_000))
        .gas_limit(21_000);

    let tx_hash1 = *wallet.send_transaction(tx1).await.unwrap().tx_hash();
    let receipt1 = network.run_until_receipt(&wallet, &tx_hash1, 100).await;

    let filter = serde_json::json!({
        "fromBlock": receipt1.block_number.unwrap(),
        "toBlock": receipt1.block_number.unwrap(),
        "fromAddress": [wallet.default_signer_address()],
        "toAddress": [to_addr],
    });

    let response: Value = wallet
        .client()
        .request("trace_filter", [filter])
        .await
        .expect("Failed to call trace_filter API");

    let traces: Vec<TraceResults> = serde_json::from_value(response).unwrap();
    assert!(!traces.is_empty());

    // Verify trace contains expected addresses
    for trace in traces {
        for trace in trace.trace {
            let action = trace.action;
            let (from_address_result, to_address_result) = match action {
                alloy::rpc::types::trace::parity::Action::Call(call_action) => {
                    (call_action.from, call_action.to)
                }
                _ => panic!("Unexpected action type"),
            };
            assert_eq!(from_address_result.0, wallet.default_signer_address().0);
            assert_eq!(to_address_result.0, to_addr.0);
        }
    }
}

#[zilliqa_macros::test]
async fn trace_filter_pagination(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create multiple transactions
    let mut receipts = Vec::new();
    for _ in 0..5 {
        let to_addr = Address::random();
        let tx = TransactionRequest::default()
            .to(to_addr)
            .value(U256::from(1_000))
            .gas_limit(21_000);

        let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();
        receipts.push(network.run_until_receipt(&wallet, &tx_hash, 100).await);
    }

    let first_block = receipts.first().unwrap().block_number.unwrap();
    let last_block = receipts.last().unwrap().block_number.unwrap();

    // Test pagination
    let filter = serde_json::json!({
        "fromBlock": first_block,
        "toBlock": last_block,
        "after": 0,
        "count": 2
    });

    let response: Value = wallet
        .client()
        .request("trace_filter", [filter])
        .await
        .expect("Failed to call trace_filter API");

    let traces: Vec<TraceResults> = serde_json::from_value(response).unwrap();
    assert_eq!(traces.len(), 2);
}
