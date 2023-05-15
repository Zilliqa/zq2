mod manual_consensus;

use crate::manual_consensus::ManualConsensus;
use tokio::time::{sleep, Duration};
use zilliqa::crypto::SecretKey;
use zilliqa::node_launcher::NodeLauncher;
use zilliqa::state::Address;

#[tokio::test]
async fn test_networked_block_production() {
    // tracing_subscriber::fmt::init();

    let mut nodes_vec = Vec::new();
    for _ in 0..4 {
        let secret_key = SecretKey::new().unwrap();
        let mut launcher = NodeLauncher::new(secret_key, toml::from_str("").unwrap()).unwrap();
        let node = launcher.get_node_handle();
        tokio::spawn(async move { launcher.start_p2p_node(0).await });
        nodes_vec.push(node);
    }
    let timeout = 40; // seconds
    for _ in 0..timeout {
        sleep(Duration::from_secs(1)).await;
        if nodes_vec[0]
            .lock()
            .unwrap()
            .get_latest_block()
            .map_or(0, |block| block.view)
            >= 10
        {
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
    let tx = zilliqa::state::NewTransaction {
        nonce: 0,
        gas_price: 0,
        gas_limit: 1,
        from_addr: Address::DEPLOY_CONTRACT,
        to_addr: Address::DEPLOY_CONTRACT,
        amount: 0,
        payload: vec![],
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
