use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::{Provider, ext::DebugApi},
    rpc::types::state::StateOverridesBuilder,
    sol,
};
use alloy_rpc_types_trace::geth::{
    GethDebugTracerType, GethDebugTracingCallOptions, GethDebugTracingOptions,
};

use crate::{Network, deployed_contract};

// https://github.com/ethereum/go-ethereum/blob/master/eth/tracers/js/internal/tracers/opcount_tracer.js
fn opcount_tracer_js() -> &'static str {
    r#"
    {
	count: 0,
	step: function(log, db) { this.count++ },
	fault: function(log, db) { },
	result: function(ctx, db) { return this.count }
    }
    "#
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/Erc4337.sol"
);
#[zilliqa_macros::test(bundler_rpc)]
async fn eth_call_with_state_overrides(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let address = Address::random();

    // balance should be zero
    network.run_until_block_finalized(5, 100).await.unwrap();
    let bal = wallet.get_balance(address).await.unwrap();
    assert!(bal.is_zero());

    // we need to use the deployed bytecode, not compiled bytecode
    let bytecode = deployed_contract("tests/it/contracts/Erc4337.sol", "Erc4337");
    // deploy and run fake contract and fake balance
    let state_overrides = StateOverridesBuilder::with_capacity(1)
        .with_code(address, bytecode)
        .with_balance(address, U256::from(0x100000))
        .build();
    let contract = Erc4337::new(address, &wallet);
    let value = contract
        .getBalance()
        .state(state_overrides)
        .call()
        .await
        .unwrap();
    assert_eq!(value, U256::from(0x100000));

    // balance still zero
    let bal = wallet.get_balance(address).await.unwrap();
    assert!(bal.is_zero());
}

#[zilliqa_macros::test(bundler_rpc)]
async fn debug_trace_call_js_tracer(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let address = Address::random();

    // balance should be zero
    network.run_until_block_finalized(5, 100).await.unwrap();
    let bal = wallet.get_balance(address).await.unwrap();
    assert!(bal.is_zero());

    // we need to use the deployed bytecode, not compiled bytecode
    let bytecode = deployed_contract("tests/it/contracts/Erc4337.sol", "Erc4337");
    // deploy and run fake contract and fake balance
    let state_overrides = StateOverridesBuilder::with_capacity(1)
        .with_code(address, bytecode)
        .with_balance(address, U256::from(0x100000))
        .build();
    let contract = Erc4337::new(address, &wallet);
    let result = wallet
        .debug_trace_call(
            contract.getNumber().into_transaction_request(),
            BlockNumberOrTag::Latest.into(),
            GethDebugTracingCallOptions {
                tracing_options: GethDebugTracingOptions {
                    tracer: Some(GethDebugTracerType::JsTracer(
                        opcount_tracer_js().to_string(),
                    )),
                    timeout: Some("10s".to_string()),
                    ..Default::default()
                },
                state_overrides: Some(state_overrides),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(result.is_js());
    assert!(result.try_into_json_value().unwrap().is_number());
}
