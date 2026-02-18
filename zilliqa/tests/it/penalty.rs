use std::collections::HashMap;

use alloy::eips::BlockId;
use tracing::info;
use zilliqa::constants::{LAG_BEHIND_CURRENT_VIEW, MISSED_VIEW_THRESHOLD, MISSED_VIEW_WINDOW};

use crate::Network;

// test if an online node is excluded from block production while it is jailed
#[zilliqa_macros::test]
async fn jailed_node_must_not_propose_blocks(mut network: Network) {
    // wait until a certain number of blocks has been produced
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index).get_finalized_height().unwrap()
                    >= LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW
            },
            10000,
        )
        .await
        .unwrap();

    // temporarily disconnect the first node to prevent it from proposing blocks
    network.disconnect_node(0);
    let jailed_leader = network.get_node(0).consensus.read().public_key();

    tracing::error!(
        "Disconnected leader: {:?}",
        alloy::hex::encode(jailed_leader.as_bytes())
    );

    // wait until the node is jailed
    // note that if there is only one node that is not proposing blocks, it will always be the first among the jailed nodes
    network
        .run_until(
            |n| {
                let node_1 = &n.get_node(1);
                let current_view = node_1.get_current_view().unwrap();
                let consensus = node_1.consensus.read();
                let view_history = consensus.state().view_history.read();
                let missed_views = &view_history.missed_views;
                let missed_map = missed_views
                    .iter()
                    .filter(|&(view, _)| {
                        *view
                            >= current_view
                                .saturating_sub(LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW)
                            && *view < current_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW)
                    })
                    .fold(HashMap::new(), |mut acc, (view, leader)| {
                        let id = leader.as_bytes();
                        acc.entry(id)
                            .and_modify(|views: &mut Vec<u64>| views.push(*view))
                            .or_insert_with(|| vec![*view]);
                        acc
                    });
                let jailed = missed_map
                    .iter()
                    .find(|&(_, views)| views.len() >= MISSED_VIEW_THRESHOLD);
                if let Some((id, views)) = jailed {
                    tracing::error!(current_view, leader = ?alloy::hex::encode(id), ?views, "jailed in");
                }
                jailed.is_some() && jailed.unwrap().0.to_vec() == jailed_leader.as_bytes()
            },
            1000,
        )
        .await
        .unwrap();

    // reconnect and sync up the first node so that it could propose blocks again if it were not jailed
    network.connect_node(0);
    network.run_until_synced(0).await;

    // check if the first node proposed any of the blocks produced while it was jailed
    network
        .run_until(
            |n| {
                let node_1 = &n.get_node(1);
                if let Ok(Some(current_block)) = node_1.get_block(BlockId::latest()) {
                    let consensus = node_1.consensus.read();
                    let view_history = consensus.state().view_history.read();
                    let missed_views = &view_history.missed_views;
                    let missed_map = missed_views
                        .iter()
                        .filter(|&(view, _)| {
                            *view
                                >= current_block
                                    .view()
                                    .saturating_sub(LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW)
                                && *view
                                    < current_block.view().saturating_sub(LAG_BEHIND_CURRENT_VIEW)
                        })
                        .fold(HashMap::new(), |mut acc, (view, leader)| {
                            let id = leader.as_bytes();
                            acc.entry(id)
                                .and_modify(|views: &mut Vec<u64>| views.push(*view))
                                .or_insert_with(|| vec![*view]);
                            acc
                        });
                    let jailed = missed_map
                        .iter()
                        .find(|&(_, views)| views.len() >= MISSED_VIEW_THRESHOLD);
                    if jailed.is_some() {
                        assert!(
                            current_block.verify(jailed_leader).is_err(),
                            "block {} in view {} proposed by jailed leader: {:?}",
                            current_block.number(),
                            current_block.view(),
                            alloy::hex::encode(jailed_leader.as_bytes())
                        );
                    }
                    jailed.is_none()
                } else {
                    false
                }
            },
            10000,
        )
        .await
        .unwrap();
}

// test if timeouts are avoided while an offline node is jailed
#[zilliqa_macros::test]
async fn jailed_node_must_not_cause_timeouts(mut network: Network) {
    // wait until a certain number of blocks has been produced
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index).get_finalized_height().unwrap()
                    >= LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW
            },
            10000,
        )
        .await
        .unwrap();

    // temporarily disconnect the first node to prevent it from proposing blocks
    network.disconnect_node(0);

    // wait until the node is jailed
    // note that if there is only one node that is not proposing blocks, it will always be the first among the jailed nodes
    network
        .run_until(
            |n| {
                let node_1 = &n.get_node(1);
                let current_view = node_1.get_current_view().unwrap();
                let consensus = node_1.consensus.read();
                let view_history = consensus.state().view_history.read();
                let missed_views = &view_history.missed_views;
                let missed_map = missed_views
                    .iter()
                    .filter(|&(view, _)| {
                        *view
                            >= current_view
                                .saturating_sub(LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW)
                            && *view < current_view.saturating_sub(LAG_BEHIND_CURRENT_VIEW)
                    })
                    .fold(HashMap::new(), |mut acc, (view, leader)| {
                        let id = (leader.as_bytes()[..3]).to_vec();
                        acc.entry(id)
                            .and_modify(|views: &mut Vec<u64>| views.push(*view))
                            .or_insert_with(|| vec![*view]);
                        acc
                    });
                let jailed = missed_map
                    .iter()
                    .find(|&(_, views)| views.len() >= MISSED_VIEW_THRESHOLD);
                if let Some((id, views)) = jailed {
                    info!(current_view, id = &id[..3], ?views, "jailed in");
                }
                jailed.is_some()
            },
            1000,
        )
        .await
        .unwrap();

    let jailed_view = network.get_node(1).get_current_view().unwrap();

    // wait for a block to be produced in the view in which the first node got jailed
    network
        .run_until(
            |n| {
                if let Ok(Some(current_block)) = n.get_node(1).get_block(BlockId::latest()) {
                    current_block.view() == jailed_view
                } else {
                    false
                }
            },
            10000,
        )
        .await
        .unwrap();

    let jailed_block = network
        .get_node(1)
        .get_block(BlockId::latest())
        .unwrap()
        .unwrap();
    info!(
        gap = jailed_block.view() - jailed_block.number(),
        view = jailed_block.view(),
        number = jailed_block.number(),
        "block produced not the by jailed leader had"
    );

    // check if there are any views missing between blocks produced while the first node was jailed
    network
        .run_until(
            |n| {
                let node_1 = &n.get_node(1);
                if let Ok(Some(current_block)) = node_1.get_block(BlockId::latest()) {
                    let consensus = node_1.consensus.read();
                    let view_history = consensus.state().view_history.read();
                    let missed_views = &view_history.missed_views;
                    let missed_map = missed_views
                        .iter()
                        .filter(|&(view, _)| {
                            *view
                                >= current_block
                                    .view()
                                    .saturating_sub(LAG_BEHIND_CURRENT_VIEW + MISSED_VIEW_WINDOW)
                                && *view
                                    < current_block.view().saturating_sub(LAG_BEHIND_CURRENT_VIEW)
                        })
                        .fold(HashMap::new(), |mut acc, (view, leader)| {
                            let id = (leader.as_bytes()[..3]).to_vec();
                            acc.entry(id)
                                .and_modify(|views: &mut Vec<u64>| views.push(*view))
                                .or_insert_with(|| vec![*view]);
                            acc
                        });
                    let jailed = missed_map
                        .iter()
                        .find(|&(_, views)| views.len() >= MISSED_VIEW_THRESHOLD);
                    if jailed.is_some() {
                        assert!(
                            current_block.view() - current_block.number()
                                == jailed_block.view() - jailed_block.number(),
                            "block {} in view {} proposed after a missed view",
                            current_block.number(),
                            current_block.view()
                        );
                    }
                    jailed.is_none()
                } else {
                    false
                }
            },
            10000,
        )
        .await
        .unwrap();
}
