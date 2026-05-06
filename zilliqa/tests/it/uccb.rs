use alloy::{
    primitives::{Address, Bytes},
    sol,
    sol_types::SolEvent as _,
};

use crate::{Network, deploy_contract};

sol!(
    #[sol(rpc)]
    "tests/it/contracts/DummyBridge.sol"
);
#[zilliqa_macros::test]
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
