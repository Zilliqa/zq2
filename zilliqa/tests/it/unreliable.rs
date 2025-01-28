use crate::Network;

#[zilliqa_macros::test]
async fn blocks_are_produced_while_a_node_restarts(mut network: Network) {
    let restarted_node = network.random_index();
    let wallet = network.wallet_of_node(restarted_node).await;

    // Select a wallet connected to a different node, so we can query the network when the first node is disconnected.
    let other_wallet = loop {
        let i = network.random_index();
        if i != restarted_node {
            break i;
        }
    };
    let other_wallet = network.wallet_of_node(other_wallet).await;

    // Produce a few blocks to start with. Enough for everyone to join the consensus committee.
    // TODO(#721): Once the committee is visible in the API, we can avoid waiting as long.
    network.run_until_block(&wallet, 8.into(), 400).await;

    // Disconnect the node we are 'restarting'.
    network.disconnect_node(restarted_node);

    // Produce 2 more blocks.
    network.run_until_block(&other_wallet, 10.into(), 400).await;

    // Reconnect the 'restarted' node.
    network.connect_node(restarted_node);

    // TODO(#721): We should assert here that a new view occurred if-and-only-if the 'restarted' node was the proposer
    // of blocks 3 or 4. This would tell us that we aren't producing new views unnecessarily.

    // Ensure more blocks are produced.
    network.run_until_block(&wallet, 12.into(), 400).await;
}
