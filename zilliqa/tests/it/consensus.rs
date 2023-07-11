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

    let index = network.add_node();

    network
        .run_until(
            |n| n.node_at(index).get_latest_block().map_or(0, |b| b.view()) >= 10,
            500,
        )
        .await
        .unwrap();
}
