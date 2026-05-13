use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ext::DebugApi},
    rpc::types::state::StateOverridesBuilder,
    sol,
    sol_types::SolEvent as _,
};
use alloy_rpc_types_trace::geth::{
    GethDebugTracerType, GethDebugTracingCallOptions, GethDebugTracingOptions,
};

use crate::{Network, deploy_contract, deployed_contract};

fn validation_tracer_js() -> &'static str {
    include_str!("js/validationTracerV0_7.js").trim_end_matches(";export{};")
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
async fn debug_trace_call_with_state_overrides(mut network: Network) {
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
    // get block number - should not fail
    let value = contract
        .getNumber()
        .state(state_overrides.clone())
        .call()
        .await;
    assert!(value.is_ok());

    // debug
    let result = wallet
        .debug_trace_call(
            contract.getNumber().into_transaction_request(),
            BlockNumberOrTag::Latest.into(),
            GethDebugTracingCallOptions {
                tracing_options: GethDebugTracingOptions {
                    tracer: Some(GethDebugTracerType::JsTracer(
                        validation_tracer_js().to_string(),
                    )),
                    // timeout: Some(self.tracer_timeout.clone()),
                    ..Default::default()
                },
                state_overrides: Some(state_overrides),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    println!("{result:?}");

    // balance still zero
    let bal = wallet.get_balance(address).await.unwrap();
    assert!(bal.is_zero());
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/DummyBridge.sol"
);
#[zilliqa_macros::test(bundler_rpc)]
async fn emits_message_sent(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (address, _hash) = deploy_contract(
        "tests/it/contracts/DummyBridge.sol",
        "DummyBridge",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let recipient = format!(
        "eip155:{}:{}",
        network.node_at(0).chain_id.eth,
        Address::random()
    );

    let contract = zilliqa::uccb::IERC7786GatewaySource::new(address, &wallet);
    let hash = *contract
        .sendMessage(
            Bytes::copy_from_slice(recipient.as_bytes()),
            Bytes::new(),
            Vec::new(),
        )
        .send()
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;
    assert!(receipt.logs().len() == 1);

    let log = receipt.logs().first().unwrap();
    let event =
        zilliqa::uccb::IERC7786GatewaySource::MessageSent::decode_log_data(log.data()).unwrap();
    assert_eq!(
        event.recipient.iter().as_slice(),
        recipient.as_bytes(),
        "recipient mismatch"
    );

    tracing::info!(
        "MessageSent({},{},{});",
        event.sendId.to_string(),
        std::str::from_utf8(event.sender.iter().as_slice()).unwrap(),
        std::str::from_utf8(event.recipient.iter().as_slice()).unwrap(),
    );
}
