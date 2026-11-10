use std::sync::{Arc, Mutex};

use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use zilliqa::cfg::ForkDelta;

use crate::Network;

#[tokio::test]
async fn sunset_zq2_keeps_producing_and_syncing_empty_blocks() {
    zilliqa::time::with_fake_time(async {
        let sockets = tempfile::tempdir().unwrap();
        let mut network = Network::new(
            Arc::new(Mutex::new(ChaCha8Rng::seed_from_u64(7))),
            4,
            7,
            "http://127.0.0.1:1".into(),
            "".into(),
            false,
            10,
            false,
            None,
            sockets.path().to_str().unwrap().into(),
            false,
        );
        let schedule = vec![ForkDelta {
            at_height: 10,
            sunset_zq2: Some(true),
            ..Default::default()
        }];
        let install_fork = |network: &Network, index| {
            let node = network.get_node(index);
            let mut c = node.consensus.write();
            c.config.consensus.forks = schedule.clone();
            let forks = c.config.consensus.get_forks().unwrap();
            c.state_mut().forks = forks;
        };
        for index in 0..4 {
            install_fork(&network, index);
        }
        let wallet = network.genesis_wallet().await;
        network.run_until_block(&wallet, 3, 100).await;
        let tx = wallet
            .send_transaction(
                TransactionRequest::default()
                    .with_to(Address::repeat_byte(42))
                    .with_value(U256::from(1)),
            )
            .await
            .unwrap()
            .tx_hash()
            .to_owned();
        network.run_until_receipt(&wallet, &tx, 100).await;

        let queued = wallet
            .send_transaction(
                TransactionRequest::default()
                    .with_to(Address::repeat_byte(43))
                    .with_nonce(50),
            )
            .await
            .unwrap()
            .tx_hash()
            .to_owned();
        network.run_until_block(&wallet, 25, 500).await;
        let frozen = wallet
            .get_block(9.into())
            .await
            .unwrap()
            .unwrap()
            .header
            .state_root;
        for height in 10..=25 {
            let block = wallet.get_block(height.into()).await.unwrap().unwrap();
            assert_eq!(block.header.state_root, frozen, "state changed at {height}");
            assert!(block.transactions.is_empty());
            assert_eq!(block.header.gas_used, 0);
        }
        assert!(
            wallet
                .get_transaction_receipt(queued)
                .await
                .unwrap()
                .is_none()
        );
        let error = wallet
            .send_transaction(
                TransactionRequest::default()
                    .with_to(Address::repeat_byte(44))
                    .with_nonce(1)
                    .with_gas_limit(21_000)
                    .with_max_fee_per_gas(10_000_000_000_000)
                    .with_max_priority_fee_per_gas(0),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("sunset_zq2"), "{error}");
        assert_eq!(
            wallet
                .get_transaction_count(wallet.default_signer_address())
                .await
                .unwrap(),
            1
        );

        let index = network.add_node();
        install_fork(&network, index);
        network
            .run_until(
                |n| n.get_node(index).get_finalized_height().unwrap() >= 25,
                1000,
            )
            .await
            .unwrap();
        let node = network.get_node(index);
        let c = node.consensus.read();
        assert_eq!(c.state().root_hash().unwrap().0, frozen.0);
    })
    .await;
}
