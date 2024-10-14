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
use primitive_types::{H160, H256};
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
    control_wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    key: NodePublicKey,
    peer_id: PeerId,
    stake: u128,
    reward_address: H160,
    pop: blsful::ProofOfPossession<Bls12381G2Impl>,
) -> H256 {
    // Transfer the new validator enough ZIL to stake.
    let tx = TransactionRequest::pay(reward_address, stake);
    let hash = control_wallet
        .send_transaction(tx, None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(control_wallet, hash, 80).await;

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
    let hash = control_wallet
        .send_transaction(tx, None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(control_wallet, hash, 80).await;
    hash
}

async fn current_epoch(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    block: Option<u64>,
) -> u64 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .data(contracts::deposit::CURRENT_EPOCH.encode_input(&[]).unwrap());
    let response = wallet
        .call(&tx.into(), block.map(|b| b.into()))
        .await
        .unwrap();
    let epoch = contracts::deposit::CURRENT_EPOCH
        .decode_output(&response)
        .unwrap()
        .remove(0)
        .into_uint()
        .unwrap()
        .as_u64();
    let current_block = block.unwrap_or(wallet.get_block_number().await.unwrap().as_u64());

    // Sanity check that epochs are calculated correctly (assuming `blocks_per_epoch = 2`).
    assert_eq!(epoch, current_block / 2);

    epoch
}

async fn unstake_amount(network: &mut Network, control_wallet: &Wallet, amount: u128) -> H256 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .data(
            contracts::deposit::UNSTAKE
                .encode_input(&[Token::Uint(amount.into())])
                .unwrap(),
        )
        .gas(10000000); // TODO: Why needed?
    let hash = control_wallet
        .send_transaction(tx, None)
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(control_wallet, hash, 100).await;
    assert_eq!(receipt.status.unwrap().as_u64(), 1);
    hash
}

async fn get_stake(wallet: &Wallet, staker: &NodePublicKey) -> u128 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT.into_array()))
        .data(
            contracts::deposit::GET_STAKE
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap(),
        );
    let output = wallet.call(&tx.into(), None).await.unwrap();

    contracts::deposit::GET_STAKE
        .decode_output(&output)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap()
        .as_u128()
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

#[zilliqa_macros::test(blocks_per_epoch = 2)]
async fn validators_can_join_and_become_proposer(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // randomise the current epoch state and current leader
    let blocks_to_prerun = network.rng.lock().unwrap().gen_range(0..8);
    network
        .run_until_block(&wallet, blocks_to_prerun.into(), 100)
        .await;

    let index = network.add_node();
    let new_validator_key = network.get_node_raw(index).secret_key;
    let reward_address = H160::random_using(&mut network.rng.lock().unwrap().deref_mut());

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);
    assert!(!stakers.contains(&new_validator_key.node_public_key()));

    let deposit_hash = deposit_stake(
        &mut network,
        &wallet,
        new_validator_key.node_public_key(),
        new_validator_key.to_libp2p_keypair().public().to_peer_id(),
        32 * 10u128.pow(18),
        reward_address,
        new_validator_key.pop_prove(),
    )
    .await;

    let deposit_block = wallet
        .get_transaction_receipt(deposit_hash)
        .await
        .unwrap()
        .unwrap()
        .block_number
        .unwrap()
        .as_u64();

    // The new validator should become part of the committee exactly two epochs after the one in which the deposit was
    // made.
    let deposit_epoch = current_epoch(&wallet, Some(deposit_block)).await;
    network
        .run_until_async(
            || async {
                let should_be_in_committee =
                    current_epoch(&wallet, None).await == deposit_epoch + 2;

                let stakers = get_stakers(&wallet).await;
                if !should_be_in_committee {
                    assert_eq!(stakers.len(), 4);
                    assert!(!stakers.contains(&new_validator_key.node_public_key()));
                    false // Keep running
                } else {
                    assert_eq!(stakers.len(), 5);
                    assert!(stakers.contains(&new_validator_key.node_public_key()));
                    true
                }
            },
            200,
        )
        .await
        .unwrap();

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

#[zilliqa_macros::test(blocks_per_epoch = 2)]
async fn validators_can_unstake(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // randomise the current epoch state and current leader
    let blocks_to_prerun = network.rng.lock().unwrap().gen_range(0..8);
    network
        .run_until_block(&wallet, blocks_to_prerun.into(), 100)
        .await;

    let validator_idx = network.random_index();
    let validator_blskey = network
        .get_node_raw(validator_idx)
        .secret_key
        .node_public_key();
    let validator_control_wallet = network
        .wallet_from_key(network.get_node_raw(validator_idx).onchain_key.clone())
        .await;
    fund_wallet(&mut network, &wallet, &validator_control_wallet).await;

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);
    assert!(stakers.contains(&validator_blskey));

    // unstake validator's entire stake
    let stake = get_stake(&wallet, &validator_blskey).await;
    let unstake_hash = unstake_amount(&mut network, &validator_control_wallet, stake).await;
    let unstake_block = wallet
        .get_transaction_receipt(unstake_hash)
        .await
        .unwrap()
        .unwrap()
        .block_number
        .unwrap()
        .as_u64();

    // The validator should leave the committee exactly two epochs after the one in which the deposit was made.
    let unstake_epoch = current_epoch(&wallet, Some(unstake_block)).await;
    network
        .run_until_async(
            || async {
                let should_be_in_committee =
                    current_epoch(&wallet, None).await != unstake_epoch + 2;

                let stakers = get_stakers(&wallet).await;
                if should_be_in_committee {
                    assert_eq!(stakers.len(), 4);
                    assert!(stakers.contains(&validator_blskey));
                    false // Keep running
                } else {
                    assert_eq!(stakers.len(), 3);
                    assert!(!stakers.contains(&validator_blskey));
                    true
                }
            },
            200,
        )
        .await
        .unwrap();

    // ensure network still runs well
    network
        .run_until_async(
            || async {
                let stakers = get_stakers(&wallet).await;
                assert_eq!(stakers.len(), 3);
                assert!(!stakers.contains(&validator_blskey));
                wallet.get_block_number().await.unwrap().as_u64() >= unstake_block + 15
            },
            1000,
        )
        .await
        .unwrap();
}

// TODO: Tests for:
// * partial unstaking staying above the minimum
// * partial unstaking under the minimum (should fail)
// * increase stake
// * updating staker details (reward address)
// * disallow access to callers other than the controlAddress
// * withdraw stake after 2 weeks