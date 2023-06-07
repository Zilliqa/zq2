use crate::Network;

#[tokio::test]
async fn sha3() {
    let network = Network::new(4);
    let provider = network.provider(0);

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#web3_sha3
    let result: String = provider
        .request("web3_sha3", ["0x68656c6c6f20776f726c64"])
        .await
        .unwrap();
    assert_eq!(
        result,
        "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
    )
}
