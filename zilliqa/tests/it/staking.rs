use std::ops::DerefMut;

use blsful::{vsss_rs::ShareIdentifier, Bls12381G2Impl};
use ethabi::Token;
use ethers::{
    middleware::SignerMiddleware,
    providers::{Middleware, Provider},
    signers::LocalWallet,
    types::{BlockId, BlockNumber, TransactionRequest},
};
use libp2p::PeerId;
use primitive_types::H160;
use rand::Rng;
use tracing::{info, trace};
use zilliqa::{contracts, crypto::NodePublicKey, state::contract_addr};

use crate::{fund_wallet, LocalRpcClient, Network, Wallet};

async fn check_miner_got_reward(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    block: impl Into<BlockId> + Send + Sync,
) {
    let block = wallet.get_block(block).await.unwrap().unwrap();
    let miner = block.author.unwrap();
    let balance_before = wallet
        .get_balance(miner, Some((block.number.unwrap() - 1).into()))
        .await
        .unwrap();
    let balance_after = wallet
        .get_balance(miner, Some(block.number.unwrap().into()))
        .await
        .unwrap();

    assert!(balance_before < balance_after);
}

async fn deposit_stake(
    network: &mut Network,
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    key: NodePublicKey,
    peer_id: PeerId,
    stake: u128,
    reward_address: H160,
    pop: blsful::ProofOfPossession<Bls12381G2Impl>,
) {
    // Transfer the new validator enough ZIL to stake.
    let tx = TransactionRequest::pay(reward_address, stake);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    network.run_until_receipt(wallet, hash, 80).await;

    // Stake the new validator's funds.
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .value(stake)
        .data(
            contracts::deposit::DEPOSIT
                .encode_input(&[
                    Token::Bytes(key.as_bytes()),
                    Token::Bytes(peer_id.to_bytes()),
                    Token::Bytes(pop.0.to_compressed().to_vec()),
                    Token::Address(reward_address),
                ])
                .unwrap(),
        );
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    network.run_until_receipt(wallet, hash, 80).await;
}

async fn remove_staker(network: &mut Network, wallet: &Wallet, key: NodePublicKey) {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .data(
            contracts::deposit::TEMP_REMOVE_STAKER
                .encode_input(&[Token::Bytes(key.as_bytes())])
                .unwrap(),
        );
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    network.run_until_receipt(wallet, hash, 50).await;
}

async fn get_stakers(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
) -> Vec<NodePublicKey> {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .data(contracts::deposit::GET_STAKERS.encode_input(&[]).unwrap());
    let stakers = wallet.call(&tx.into(), None).await.unwrap();
    let stakers = contracts::deposit::GET_STAKERS
        .decode_output(&stakers)
        .unwrap()[0]
        .clone()
        .into_array()
        .unwrap();

    stakers
        .into_iter()
        .map(|k| NodePublicKey::from_bytes(&k.into_bytes().unwrap()).unwrap())
        .collect()
}

async fn get_minimum_deposit(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
) -> u128 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .data(contracts::deposit::MIN_DEPOSIT.encode_input(&[]).unwrap());
    let deposit = wallet.call(&tx.into(), None).await.unwrap();

    let deposit = contracts::deposit::MIN_DEPOSIT
        .decode_output(&deposit)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    deposit.as_u128()
}

#[zilliqa_macros::test]
async fn minimum_stake_is_properly_set(mut network: Network) {
    let wallet = network.random_wallet().await;

    let deposit = get_minimum_deposit(&wallet).await;
    assert_eq!(
        deposit,
        *network.nodes[0]
            .inner
            .lock()
            .unwrap()
            .config
            .consensus
            .minimum_stake
    );
}

#[zilliqa_macros::test]
async fn rewards_are_sent_to_reward_address_of_proposer(mut network: Network) {
    let wallet = network.random_wallet().await;

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);

    network.run_until_block(&wallet, 1.into(), 80).await;

    check_miner_got_reward(&wallet, 1).await;
}

#[zilliqa_macros::test]
async fn validators_can_join_and_become_proposer(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let index = network.add_node();
    let new_validator_key = network.get_node_raw(index).secret_key;
    let reward_address = H160::random_using(&mut network.rng.lock().unwrap().deref_mut());

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);
    assert!(!stakers.contains(&new_validator_key.node_public_key()));

    let pop = new_validator_key.pop_prove();

    deposit_stake(
        &mut network,
        &wallet,
        new_validator_key.node_public_key(),
        new_validator_key.to_libp2p_keypair().public().to_peer_id(),
        32 * 10u128.pow(18),
        reward_address,
        pop,
    )
    .await;

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 5);
    assert!(stakers.contains(&new_validator_key.node_public_key()));

    // Check the new validator eventually gets to be a block proposer.
    network
        .run_until_async(
            || async {
                wallet
                    .get_block(BlockNumber::Latest)
                    .await
                    .unwrap()
                    .unwrap()
                    .author
                    .unwrap()
                    == reward_address
            },
            500,
        )
        .await
        .unwrap();
    check_miner_got_reward(&wallet, BlockNumber::Latest).await;
}

#[zilliqa_macros::test]
async fn block_proposers_are_selected_proportionally_to_their_stake(mut network: Network) {
    // The starting configuration is 4 nodes with a stake of 32 ZIL each. We'll add a 5th node with a stake of 1024 ZIL
    // and check that it produces a statistically significant proportion of the subsequent blocks.

    let wallet = network.genesis_wallet().await;

    let index = network.add_node();
    let new_validator_key = network.get_node_raw(index).secret_key;
    let reward_address = H160::random_using(&mut network.rng.lock().unwrap().deref_mut());

    let pop = new_validator_key.pop_prove();

    deposit_stake(
        &mut network,
        &wallet,
        new_validator_key.node_public_key(),
        new_validator_key.to_libp2p_keypair().public().to_peer_id(),
        1024 * 10u128.pow(18),
        reward_address,
        pop,
    )
    .await;

    // Start counting at the point where the new validator becomes a block proposer. This guarantees it is now part of
    // the consensus committee.
    network
        .run_until_async(
            || async {
                wallet
                    .get_block(BlockNumber::Latest)
                    .await
                    .unwrap()
                    .unwrap()
                    .author
                    .unwrap()
                    == reward_address
            },
            1000,
        )
        .await
        .unwrap();

    let current_block = wallet.get_block_number().await.unwrap().as_u64();
    info!(current_block, ?reward_address, "deposit staked");
    network
        .run_until_async(
            || async { wallet.get_block_number().await.unwrap().as_u64() >= current_block + 20 },
            1000,
        )
        .await
        .unwrap();

    let mut proposers = vec![];
    for b in current_block..=(current_block + 20) {
        let block = wallet.get_block(b).await.unwrap().unwrap();
        proposers.push(block.author.unwrap());
    }
    trace!(?proposers);

    // The chance of our new node being the proposer in any single block should be `1024 / (1024 + 32 * 4) ~= 0.89`.
    // Taking a binomial distribution of `X ~ bin(20, 0.89)`, we select a boundary value of 6 blocks, because
    // `P(X < 6) ~= 4.35 * 10^-11`. This is false-negative rate of this test. Conversely, if we take `Y ~ bin(20, 0.2)`
    // as one of the possible distributions if our implemention is wrong (if proposers are equally likely), we get
    // `P(Y < 6) ~= 0.80`, meaning this test is likely to (correctly) fail.
    assert!(
        proposers
            .iter()
            .filter(|addr| **addr == reward_address)
            .count()
            >= 6
    );
}

#[zilliqa_macros::test]
async fn validators_can_leave(mut network: Network) {
    let genesis_wallet = network.genesis_wallet().await;

    let blocks_to_prerun = network.rng.lock().unwrap().gen_range(0..5);
    network
        .run_until_block(&genesis_wallet, blocks_to_prerun.into(), 100)
        .await;

    let validator_to_remove = network.random_index();
    let validator_sending_removal = network.random_index();

    let key_to_remove = network.get_node_raw(validator_to_remove).secret_key;
    let wallet_sending_removal = network
        .wallet_from_key(
            network
                .get_node_raw(validator_sending_removal)
                .onchain_key
                .clone(),
        )
        .await;
    fund_wallet(&mut network, &genesis_wallet, &wallet_sending_removal).await;

    let stakers = get_stakers(&genesis_wallet).await;
    assert_eq!(stakers.len(), 4);
    assert!(stakers.contains(&key_to_remove.node_public_key()));

    remove_staker(
        &mut network,
        &wallet_sending_removal,
        key_to_remove.node_public_key(),
    )
    .await;

    let stakers = get_stakers(&genesis_wallet).await;
    assert_eq!(stakers.len(), 3);
    assert!(!stakers.contains(&key_to_remove.node_public_key()));

    network
        .run_until_block(&genesis_wallet, (blocks_to_prerun + 10).into(), 500)
        .await;
}
