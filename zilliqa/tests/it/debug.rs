use alloy::{
    primitives::{B256, Uint},
    rpc::types::trace::geth::TraceResult,
};
use ethers::{
    providers::Middleware,
    types::{H160, TransactionRequest},
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
    let to_addr = H160::random();
    let tx = TransactionRequest::new().to(to_addr).value(1000).gas(21000);

    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    // Wait for transaction to be mined
    let receipt = network.run_until_receipt(&wallet, tx_hash, 100).await;
    let block_number = receipt.block_number.unwrap();

    // Get trace
    let response: Vec<TraceResult> = wallet
        .provider()
        .request("debug_traceBlockByNumber", [block_number])
        .await
        .expect("Failed to call debug_traceBlockByNumber API");

    assert!(!response.is_empty());

    // Test with callTracer
    let tracer_options = serde_json::json!({
        "tracer": "callTracer"
    });

    let response: Vec<TraceResult> = wallet
        .provider()
        .request("debug_traceBlockByNumber", (block_number, tracer_options))
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
    let to_addr = H160::random();
    let tx = TransactionRequest::new().to(to_addr).value(1000).gas(21000);

    let tx_hash_sent = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    // Wait for transaction to be mined
    network.run_until_receipt(&wallet, tx_hash_sent, 100).await;

    // Get trace
    let response: TraceResult = wallet
        .provider()
        .request("debug_traceTransaction", [tx_hash_sent])
        .await
        .expect("Failed to call debug_traceTransaction API");

    match response {
        TraceResult::Success { result, tx_hash } => {
            dbg!(&result);
            let frame = result.try_into_default_frame().unwrap();
            assert_eq!(tx_hash.unwrap(), tx_hash_sent.to_fixed_bytes());
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
    let to_addr = H160::random();
    let tx = TransactionRequest::new().to(to_addr).value(1000).gas(21000);

    let tx_hash_sent = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    // Wait for transaction to be mined
    network.run_until_receipt(&wallet, tx_hash_sent, 100).await;

    // Configure callTracer
    let tracer_options = serde_json::json!({
        "tracer": "callTracer",
        "tracerConfig": {
            "onlyTopCall": false
        }
    });

    // Get trace
    let response: TraceResult = wallet
        .provider()
        .request("debug_traceTransaction", (tx_hash_sent, tracer_options))
        .await
        .expect("Failed to call debug_traceTransaction API");

    match response {
        TraceResult::Success { result, tx_hash } => {
            dbg!(&result);
            let frame = result.try_into_call_frame().unwrap();
            assert_eq!(tx_hash.unwrap(), tx_hash_sent.to_fixed_bytes());
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

    let nonexistent_hash: B256 =
        "0x1234567890123456789012345678901234567890123456789012345678901234"
            .parse()
            .unwrap();

    let response: Result<TraceResult, _> = wallet
        .provider()
        .request("debug_traceTransaction", [nonexistent_hash])
        .await;

    assert!(response.is_err());
}
