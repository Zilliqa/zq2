use crate::Network;

#[zilliqa_macros::test]
async fn block_production(mut network: Network<'_>) {
    network
        .run_until(
            |n| n.node().get_latest_block().map_or(0, |b| b.view()) >= 5,
            50,
        )
        .await
        .unwrap();
}
