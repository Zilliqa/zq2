use zilliqa::constants::{LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_WINDOW};

use crate::Network;

// test that even with some consensus messages being dropped, the network can still proceed
// note: this drops all messages, not just consensus messages, but there should only be
// consensus messages in the network anyway
#[zilliqa_macros::test(blocks_per_epoch = 100)]
async fn block_production_even_when_lossy_network(mut network: Network) {
    let index = network.random_index();
    let until_at = LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW;

    // wait until a certain number of blocks has been produced
    network
        .run_until_block_finalized(until_at, 7000)
        .await
        .unwrap();

    // now, run for another 5 blocks, but dropping 5% of the messages.
    let until_at = until_at + 5;
    let mut block_at = 0;
    for _ in 0..1000000 {
        network.randomly_drop_messages_then_tick(0.05).await;
        block_at = network.node_at(index).get_finalized_block_number().unwrap();
        if block_at >= until_at {
            break;
        }
    }

    assert!(
        block_at >= until_at,
        "block number should be at least {until_at}, but was {block_at}",
    );
}

#[zilliqa_macros::test(blocks_per_epoch = 100)]
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

    let until_at = LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW;

    // Produce a few blocks to start with: enough for everyone to join the consensus committee; and enough history for jailing.
    // TODO(#721): Once the committee is visible in the API, we can avoid waiting as long.
    // wait until at least 5 blocks have been produced
    network
        .run_until_block_finalized(until_at, 7000)
        .await
        .unwrap();

    // Disconnect the node we are 'restarting'.
    network.disconnect_node(restarted_node);

    // Produce more blocks.
    network
        .run_until_block(&other_wallet, until_at + 4, 400)
        .await;

    // Reconnect the 'restarted' node.
    network.connect_node(restarted_node);

    // TODO(#721): We should assert here that a new view occurred if-and-only-if the 'restarted' node was the proposer
    // of blocks 3 or 4. This would tell us that we aren't producing new views unnecessarily.

    // Ensure more blocks are produced.
    network.run_until_block(&wallet, until_at + 6, 400).await;
}
