use crate::Network;

#[zilliqa_macros::test]
async fn block_production(mut network: Network<'_>) {
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.view())
                    >= 5
            },
            50,
        )
        .await
        .unwrap();
}

#[zilliqa_macros::test]
async fn launch_shard(mut network: Network<'_>) {
    let wallet = network.random_wallet();

    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.view())
                    >= 5
            },
            50,
        )
        .await
        .unwrap();
}
