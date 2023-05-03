// use zilliqa::node::Node;
// use std::sync::Arc;
// use libp2p::futures::lock::Mutex;
use tokio::time::{sleep, Duration};
use zilliqa::crypto::SecretKey;
use zilliqa::node_launcher::NodeLauncher;

#[tokio::test]
async fn test_block_production() {
    // tracing_subscriber::fmt::init();

    let mut nodes_vec = Vec::new();
    for _ in 0..4 {
        let secret_key = SecretKey::new().unwrap();
        let mut launcher = NodeLauncher::new(secret_key, toml::from_str("").unwrap()).unwrap();
        let node = launcher.get_node();
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
