use alloy::providers::Provider as _;

use crate::Network;

#[zilliqa_macros::test]
async fn sha3(mut network: Network) {
    let wallet = network.random_wallet().await;

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#web3_sha3
    let result: String = wallet
        .client()
        .request("web3_sha3", ["0x68656c6c6f20776f726c64"])
        .await
        .unwrap();
    assert_eq!(
        result,
        "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
    )
}
