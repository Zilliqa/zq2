use std::{fs, ops::DerefMut};

use alloy::eips::BlockId;
use ethabi::Token;
use ethers::{providers::Middleware, types::TransactionRequest};
use k256::ecdsa::SigningKey;
use primitive_types::H160;
use rand::Rng;
use tracing::*;
use zilliqa::{
    cfg::Checkpoint,
    crypto::{Hash, SecretKey},
};

use crate::{
    Network, NewNodeOptions, TestNode, deploy_contract,
    zil::{
        deploy_scilla_contract, scilla_test_contract_code, scilla_test_contract_data,
        zilliqa_account,
    },
};

#[zilliqa_macros::test]
async fn block_and_tx_data_persistence(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    // send and include tx
    let hash = Hash(
        wallet
            .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
            .await
            .unwrap()
            .tx_hash()
            .0,
    );

    let index = network.random_index();

    network
        .run_until(
            |n| {
                n.get_node(index)
                    .get_transaction_receipt(hash)
                    .unwrap()
                    .is_some()
            },
            450,
        )
        .await
        .unwrap();

    let latest_block_number = network
        .get_node(index)
        .get_block(BlockId::latest())
        .unwrap()
        .map_or(0, |b| b.number());

    // make one block without txs
    network
        .run_until(
            |n| {
                let block = n
                    .get_node(index)
                    .get_block(BlockId::latest())
                    .unwrap()
                    .map_or(0, |b| b.number());
                block > latest_block_number
            },
            450,
        )
        .await
        .unwrap();

    let receipt = wallet
        .provider()
        .get_transaction_receipt(hash.0)
        .await
        .unwrap()
        .unwrap();

    // make one block without txs
    network
        .run_until(
            |n| {
                let block = n
                    .get_node(index)
                    .get_block(BlockId::latest())
                    .unwrap()
                    .map_or(0, |b| b.number());
                block > receipt.block_number.unwrap().as_u64()
            },
            450,
        )
        .await
        .unwrap();

    let node = network.remove_node(index);

    let inner = node.inner.read();
    let last_number = inner.number() - 2;
    let receipt = inner.get_transaction_receipt(hash).unwrap().unwrap();
    let block_with_tx = inner.get_block(receipt.block_hash).unwrap().unwrap();
    let last_block = inner.get_block(last_number).unwrap().unwrap();
    let tx = inner.get_transaction_by_hash(hash).unwrap().unwrap();
    let current_view = inner.get_current_view().unwrap();
    let finalized_view = inner.get_finalized_height().unwrap();
    // sanity check
    assert_eq!(tx.hash, hash);
    assert_eq!(block_with_tx.transactions.len(), 1);
    assert_ne!(current_view, finalized_view);

    // drop and re-create the node using the same datadir:
    drop(inner);
    let config = node.inner.read().config.clone();
    #[allow(clippy::redundant_closure_call)]
    let dir = (|mut node: TestNode| node.dir.take())(node).unwrap(); // move dir out and drop the rest of node
    let mut rng = network.rng.lock().unwrap();
    let result = crate::node(
        config,
        SecretKey::new_from_rng(rng.deref_mut()).unwrap(),
        SigningKey::random(rng.deref_mut()),
        0,
        Some(dir),
    );

    // Sometimes, the dropping Arc<Node> (by dropping the TestNode above) does not actually drop
    // the underlying Node. See: https://github.com/Zilliqa/zq2/issues/299
    // As this is very painful to debug, should only ever be relevant for tests like these, and CI
    // should run enough samples to still have decent test coverage, we simply skip the rest of the
    // test if this happens.
    let Ok((newnode, _, _, _)) = result else {
        warn!(
            "Failed to release database lock. Skipping test, with seed {}.",
            network.seed
        );
        return;
    };
    let inner = newnode.inner.read();

    // ensure all blocks created were saved up till the last one
    let loaded_last_block = inner.get_block(last_number).unwrap();
    assert!(loaded_last_block.is_some());
    assert_eq!(loaded_last_block.unwrap().hash(), last_block.hash());

    // ensure tx was saved, including its receipt
    let loaded_tx_block = inner.get_block(block_with_tx.number()).unwrap().unwrap();
    assert_eq!(loaded_tx_block.hash(), block_with_tx.hash());
    assert_eq!(loaded_tx_block.transactions.len(), 1);
    assert!(inner.get_transaction_receipt(hash).unwrap().is_some());
    assert_eq!(
        inner
            .get_transaction_by_hash(hash)
            .unwrap()
            .unwrap()
            .tx
            .into_transaction()
            .payload(),
        tx.tx.into_transaction().payload()
    );

    // ensure were back on the same view
    assert_eq!(current_view, inner.get_current_view().unwrap());
    assert_eq!(finalized_view, inner.get_finalized_height().unwrap());
}

#[zilliqa_macros::test(do_checkpoints)]
async fn checkpoints_test(mut network: Network) {
    // Populate network with transactions
    let wallet = network.genesis_wallet().await;
    let (hash, abi) = deploy_contract(
        "tests/it/contracts/Storage.sol",
        "Storage",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();

    let new_val = 3281u64;

    // set some storage items with transactions
    // Evm
    let function = abi.function("set").unwrap();
    let mut address_buf = [0u8; 20];
    network.rng.lock().unwrap().fill(&mut address_buf);
    let update_tx = TransactionRequest::new().to(contract_address).data(
        function
            .encode_input(&[
                Token::Address(address_buf.into()),
                Token::Uint(new_val.into()),
            ])
            .unwrap(),
    );
    let update_tx_hash = wallet
        .send_transaction(update_tx, None)
        .await
        .unwrap()
        .tx_hash();
    network
        .run_until_receipt(&wallet, update_tx_hash, 100)
        .await;
    // Scilla
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;
    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let scilla_contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    // Run until block 19 so that we can insert a tx in block 20 (note that this transaction may not *always* appear in the desired block, therefore we do not assert its presence later)
    network.run_until_block(&wallet, 19.into(), 400).await;

    let _hash = wallet
        .send_transaction(TransactionRequest::pay(wallet.address(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    // wait 20 blocks for checkpoint to happen - then 3 more to finalize that block
    network.run_until_block(&wallet, 33.into(), 400).await;

    let checkpoint_files = network
        .nodes
        .iter()
        .map(|node| {
            node.dir
                .as_ref()
                .unwrap()
                .path()
                .join(network.shard_id.to_string())
                .join("checkpoints")
                .join("30")
        })
        .collect::<Vec<_>>();

    let mut len_check = 0;
    for path in &checkpoint_files {
        let metadata = fs::metadata(path).unwrap();
        assert!(metadata.is_file());
        let file_len = metadata.len();
        assert!(file_len != 0);
        assert!(len_check == 0 || len_check == file_len); // len_check = 0 on first loop iteration
        len_check = file_len;
    }

    // Create new node and pass it one of those checkpoint files
    let checkpoint_path = checkpoint_files[0].to_str().unwrap().to_owned();
    let checkpoint_hash = wallet.get_block(30).await.unwrap().unwrap().hash.unwrap();
    let new_node_idx = network.add_node_with_options(NewNodeOptions {
        checkpoint: Some(Checkpoint {
            file: checkpoint_path,
            hash: Hash(checkpoint_hash.0),
        }),
        ..Default::default()
    });

    // Confirm wallet and new_node_wallet have the same block and state
    let new_node_wallet = network.wallet_of_node(new_node_idx).await;
    let latest_block_number = new_node_wallet.get_block_number().await.unwrap();
    assert_eq!(latest_block_number, 30.into());

    let block = wallet
        .get_block(latest_block_number)
        .await
        .unwrap()
        .unwrap();
    let block_from_checkpoint = new_node_wallet
        .get_block(latest_block_number)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(block.transactions, block_from_checkpoint.transactions);
    // Check access to previous block state via fetching author of current block
    assert_eq!(block.author, block_from_checkpoint.author);

    // Check storage
    // Evm
    let storage_getter = abi.function("pos1").unwrap();
    let check_storage_tx = TransactionRequest::new().to(contract_address).data(
        storage_getter
            .encode_input(&[Token::Address(address_buf.into())])
            .unwrap(),
    );
    let storage = new_node_wallet
        .call(&check_storage_tx.into(), None)
        .await
        .unwrap();
    let val = storage_getter.decode_output(&storage).unwrap();
    assert_eq!(val[0], Token::Uint(new_val.into()));
    // Scilla
    let state: serde_json::Value = network
        .random_wallet()
        .await
        .provider()
        .request("GetSmartContractState", [scilla_contract_address])
        .await
        .unwrap();
    assert_eq!(state["welcome_msg"], "default");

    // check the new node catches up and keeps up with block production
    network.run_until_synced(new_node_idx).await;
    network
        .run_until_block(&new_node_wallet, 40.into(), 400)
        .await;

    // check account nonce of old wallet
    let nonce = new_node_wallet
        .get_transaction_count(wallet.address(), None)
        .await
        .unwrap();
    assert_eq!(nonce, 4.into());
}
