use crate::Network;

#[tokio::test]
async fn block_production() {
    let mut network = Network::new(4);

    network
        .run_until(
            |n| n.node(0).get_latest_block().unwrap().map_or(0, |b| b.view()) >= 5,
            50,
        )
        .await
        .unwrap();
}
