use alloy::{
    network::TransactionBuilder,
    primitives::{Address, TxHash, U256, Uint},
    providers::Provider as _,
    rpc::types::{TransactionRequest, trace::geth::TraceResult},
};

use crate::Network;

// Tests for debug_getBadBlocks

// Tests for debug_getTrieFlushInterval

// Tests for debug_storageRangeAt

// Tests for debug_traceBlock

// Tests for debug_traceBlockByHash

// Tests for debug_traceBlockByNumber

#[zilliqa_macros::test]
async fn debug_trace_block_by_number(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create a transaction to have something to trace
    let to_addr = Address::random();
    let tx = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(1000))
        .gas_limit(21_000);

    let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();

    // Wait for transaction to be mined
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    let block_number = format!("{:#x}", receipt.block_number.unwrap());

    // Get trace
    let response: Vec<TraceResult> = wallet
        .client()
        .request("debug_traceBlockByNumber", [&block_number])
        .await
        .expect("Failed to call debug_traceBlockByNumber API");

    assert!(!response.is_empty());

    // Test with callTracer
    let tracer_options = serde_json::json!({
        "tracer": "callTracer"
    });

    let response: Vec<TraceResult> = wallet
        .client()
        .request("debug_traceBlockByNumber", (&block_number, tracer_options))
        .await
        .expect("Failed to call debug_traceBlockByNumber with tracer API");

    assert!(!response.is_empty());
}

// Tests for debug_traceCall

// Tests for debug_traceTransaction

#[zilliqa_macros::test]
async fn debug_trace_transaction_basic(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create a simple transfer transaction
    let to_addr = Address::random();
    let tx = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(1000))
        .gas_limit(21000);

    let tx_hash_sent = *wallet.send_transaction(tx).await.unwrap().tx_hash();

    // Wait for transaction to be mined
    network.run_until_receipt(&wallet, &tx_hash_sent, 100).await;

    // Get trace
    let response: TraceResult = wallet
        .client()
        .request("debug_traceTransaction", [tx_hash_sent])
        .await
        .expect("Failed to call debug_traceTransaction API");

    match response {
        TraceResult::Success { result, tx_hash } => {
            dbg!(&result);
            let frame = result.try_into_default_frame().unwrap();
            assert_eq!(tx_hash.unwrap(), tx_hash_sent);
            assert!(!frame.failed);
            assert!(frame.gas == 21000);
        }
        _ => panic!("Expected success result"),
    }
}

#[zilliqa_macros::test]
async fn debug_trace_transaction_with_call_tracer(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create a simple transfer transaction
    let to_addr = Address::random();
    let tx = TransactionRequest::default()
        .with_to(to_addr)
        .with_value(U256::from(1000))
        .with_gas_limit(21000);

    let tx_hash_sent = *wallet.send_transaction(tx).await.unwrap().tx_hash();

    // Wait for transaction to be mined
    network.run_until_receipt(&wallet, &tx_hash_sent, 100).await;

    // Configure callTracer
    let tracer_options = serde_json::json!({
        "tracer": "callTracer",
        "tracerConfig": {
            "onlyTopCall": false
        }
    });

    // Get trace
    let response: TraceResult = wallet
        .client()
        .request("debug_traceTransaction", (tx_hash_sent, tracer_options))
        .await
        .expect("Failed to call debug_traceTransaction API");

    match response {
        TraceResult::Success { result, tx_hash } => {
            dbg!(&result);
            let frame = result.try_into_call_frame().unwrap();
            assert_eq!(tx_hash.unwrap(), tx_hash_sent);
            assert!(Uint::from(21000) >= frame.gas_used);
            assert!(Uint::from(0) < frame.gas_used);
            assert!(frame.error.is_none())
        }
        _ => panic!("Expected success result"),
    }
}

#[zilliqa_macros::test]
async fn debug_trace_transaction_not_found(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let nonexistent_hash = TxHash::random();

    let response: Result<TraceResult, _> = wallet
        .client()
        .request("debug_traceTransaction", [nonexistent_hash])
        .await;

    assert!(response.is_err());
}
