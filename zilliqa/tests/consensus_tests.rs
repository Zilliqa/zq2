mod manual_consensus;

use crate::manual_consensus::ManualConsensus;
use futures::{Stream, StreamExt};
use itertools::Itertools;
use libp2p::PeerId;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use zilliqa::cfg::Config;
use zilliqa::crypto::SecretKey;
use zilliqa::message::Message;
use zilliqa::node::Node;
use zilliqa::state::{Address, Transaction};

fn node() -> (
    SecretKey,
    impl Stream<Item = (PeerId, PeerId, Message)>,
    Node,
) {
    let secret_key = SecretKey::new().unwrap();

    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let message_receiver = UnboundedReceiverStream::new(message_receiver);
    // Augment the `message_receiver` stream to include the sender's `PeerId`.
    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let message_receiver = message_receiver.map(move |(dest, message)| (peer_id, dest, message));
    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    std::mem::forget(reset_timeout_receiver);

    (
        secret_key,
        message_receiver,
        Node::new(
            Config::default(),
            secret_key,
            message_sender,
            reset_timeout_sender,
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn test_block_production() {
    let nodes = 4;
    let (keys, receivers, mut nodes): (Vec<_>, Vec<_>, Vec<_>) =
        (0..nodes).map(|_| node()).multiunzip();

    for (i, node) in nodes.iter_mut().enumerate() {
        for (j, key) in keys.iter().enumerate() {
            if i == j {
                continue;
            }
            node.add_peer(
                key.to_libp2p_keypair().public().to_peer_id(),
                key.node_public_key(),
            )
            .unwrap();
        }
    }

    let messages = futures::stream::select_all(receivers);
    // Fail if we don't reach block 10 after 100 messages.
    let mut messages = messages.take(100);

    while let Some((source, _destination, message)) = messages.next().await {
        // Currently, all messages are broadcast, so we replicate that behaviour here.
        for node in nodes.iter_mut() {
            node.handle_message(source, message.clone()).unwrap();
        }

        if nodes[0].get_latest_block().map_or(0, |b| b.view()) >= 10 {
            return;
        }
    }

    panic!("Did not reach 10 blocks produced within the timeout");
}

#[tokio::test]
async fn test_manual_block_production() {
    let mut manual_consensus = ManualConsensus::new();

    manual_consensus.mine_blocks(50).await;
}

#[tokio::test]
async fn test_manual_transaction_submission() {
    let mut manual_consensus = ManualConsensus::new();
    let tx_origin = SecretKey::new().unwrap();
    let tx = zilliqa::state::Transaction {
        nonce: 0,
        gas_price: 0,
        gas_limit: 1,
        public_key: tx_origin.tx_ecdsa_public_key(),
        signature: None,
        to_addr: Address::DEPLOY_CONTRACT,
        amount: 0,
        payload: vec![],
    };
    let tx = Transaction {
        signature: Some(tx_origin.tx_sign_ecdsa(tx.hash().as_bytes())),
        ..tx
    };
    manual_consensus.submit_transaction(tx.clone());
    manual_consensus.mine_block().await;

    manual_consensus.nodes[0]
        .node
        .lock()
        .unwrap()
        .get_transaction_by_hash(tx.hash())
        .unwrap();
}
