use crate::{CombinedJson, Context};
use ethabi::Token;

use zilliqa::state::Address;

use crate::Network;

use ethers::{providers::Middleware, types::TransactionRequest};

// #[test]
// fn try_if_is_send() {
//     let mut rng = <rand_chacha::ChaCha8Rng as rand_core::SeedableRng>::seed_from_u64(0);
//     let network = crate::Network::new(std::sync::Arc::new(std::sync::Mutex::new(rng)), 4, 0);
//     let node = network.get_node_arc(0).clone();
//     let nref = &node;
//     std::thread::spawn(move || {
//         let mut n = nref;
//     })
//     .join()
//     .unwrap();
// }

// async fn block_production() {
//     // The original test function

//     async fn inner(mut network: Network) {
//         async fn made_five_blocks(network: Box<&Network>) -> bool {
//             let index = network.random_index();
//             let node = network.get_node_arc(index).clone();
//             drop(network);
//             let node = node.lock().await;
//             node.get_latest_block().unwrap().map_or(0, |b| b.view()) >= 5
//         }

//         network.run_until_async(made_five_blocks, 50).await.unwrap();
//     }

//     // Work out what RNG seeds to run the test with.
//     let seeds: Vec<u64> = if let Some(seed) = std::env::var_os("ZQ_TEST_RNG_SEED") {
//         vec![seed.to_str().unwrap().parse().unwrap()]
//     } else {
//         let samples: usize = std::env::var_os("ZQ_TEST_SAMPLES")
//             .map(|s| s.to_str().unwrap().parse().unwrap())
//             .unwrap_or(1);
//         // Generate random seeds using the thread-local RNG.
//         rand::Rng::sample_iter(rand::thread_rng(), rand::distributions::Standard)
//             .take(samples)
//             .collect()
//     };

//     let mut set = tokio::task::JoinSet::new();

//     for seed in seeds {
//         set.spawn(async move {
//             // Set up a tracing subscriber, so we can see logs from failed test cases.
//             let subscriber = tracing_subscriber::fmt()
//                 .with_ansi(false)
//                 .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
//             let _guard = tracing_subscriber::util::SubscriberInitExt::set_default(subscriber);

//             println!("Reproduce this test run by setting ZQ_TEST_RNG_SEED={seed}");
//             let rng = <rand_chacha::ChaCha8Rng as rand_core::SeedableRng>::seed_from_u64(seed);
//             let network =
//                 crate::Network::new(std::sync::Arc::new(std::sync::Mutex::new(rng)), 4, seed);
//             // Call the original test function
//             inner(network).await;
//         });
//     }

//     while let Some(result) = set.join_next().await {
//         let () = result.unwrap();
//     }
// }

#[zilliqa_macros::test]
async fn block_production(mut network: Network) {
    async fn made_five_blocks(network: &Network, _: Context) -> bool {
        let index = network.random_index();
        network
            .get_node(index)
            .await
            .get_latest_block()
            .unwrap()
            .map_or(0, |b| b.view())
            >= 5
    }

    network
        .run_until_async(made_five_blocks, Context::default(), 50)
        .await
        .unwrap();

    let index = network.add_node(false).await;

    async fn made_ten_blocks(network: &Network, context: Context) -> bool {
        network
            .node_at(context.index.unwrap())
            .await
            .get_latest_block()
            .unwrap()
            .map_or(0, |b| b.view())
            >= 10
    }

    network
        .run_until_async(made_ten_blocks, Context::index(index), 500)
        .await
        .unwrap();
    println!("Second block run completed");
}

#[zilliqa_macros::test]
async fn launch_shard(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    async fn block_above_one(_: &Network, context: Context) -> bool {
        context
            .wallet
            .unwrap()
            .get_block_number()
            .await
            .unwrap()
            .as_u64()
            >= 1
    }

    network
        .run_until_async(block_above_one, Context::wallet(wallet), 50)
        .await
        .unwrap();

    let abi = include_str!("../../src/contracts/shard_registry.json");
    let abi = serde_json::from_str::<CombinedJson>(abi)
        .unwrap()
        .contracts
        .remove("shard_registry.sol:ShardRegistry")
        .unwrap()
        .abi;

    let shard_id = 80000u64;

    let function = abi.function("addShard").unwrap();
    let tx_request = TransactionRequest::new()
        .to(Address::SHARD_CONTRACT.0)
        .data(
            function
                .encode_input(&[Token::Uint(shard_id.into())])
                .unwrap(),
        );

    // sanity check
    assert_eq!(network.children.len(), 0);

    let tx = wallet.send_transaction(tx_request, None).await.unwrap();
    let hash = tx.tx_hash();

    async fn got_tx_hash(_: &Network, context: Context) -> bool {
        context
            .wallet
            .unwrap()
            .get_transaction_receipt(context.hash.unwrap())
            .await
            .unwrap()
            .is_some()
    }

    network
        .run_until_async(got_tx_hash, Context::wallet_and_hash(wallet, hash), 50)
        .await
        .unwrap();

    let included_block = wallet.get_block_number().await.unwrap();

    async fn block_finalized(_: &Network, context: Context) -> bool {
        context
            .wallet
            .unwrap()
            .get_block_number()
            .await
            .unwrap()
            .as_u64()
            >= context.index.unwrap() as u64 + 2
    }

    // finalize block
    network
        .run_until_async(
            block_finalized,
            Context {
                index: Some(included_block.as_usize()),
                hash: None,
                wallet: Some(wallet),
            },
            50,
        )
        .await
        .unwrap();

    // check we've spawned a shard
    network
        .run_until(|n| n.children.contains_key(&shard_id), 50)
        .await
        .unwrap();

    // check every node has spawned a shard node
    network
        .run_until(
            |n| n.children.get(&shard_id).unwrap().nodes.len() == n.nodes.len(),
            50,
        )
        .await
        .unwrap();

    // check shard is producing blocks
    network
        .children
        .get_mut(&shard_id)
        .unwrap()
        .run_until_async(
            |_| async {
                let index = network.random_index();
                network
                    .get_node(index)
                    .await
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
