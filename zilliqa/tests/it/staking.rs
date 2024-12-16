use std::ops::DerefMut;

use blsful::{inner_types::G2Projective, vsss_rs::ShareIdentifier};
use ethabi::Token;
use ethers::{
    middleware::SignerMiddleware,
    providers::{Middleware, Provider},
    signers::LocalWallet,
    types::{BlockId, BlockNumber, TransactionRequest},
};
use primitive_types::{H160, H256};
use rand::Rng;
use revm::primitives::Address;
use tracing::{info, trace};
use zilliqa::{
    contracts,
    crypto::{NodePublicKey, SecretKey},
    message::MAX_COMMITTEE_SIZE,
    state::contract_addr,
};

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
    staker_wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    new_validator_key: SecretKey,
    stake: u128,
    reward_address: H160,
    deposit_signature_raw: &G2Projective,
) -> H256 {
    // Transfer the new validator enough ZIL to stake.
    let tx = TransactionRequest::pay(staker_wallet.address(), stake + 58190476400000000000);
    let hash = control_wallet
        .send_transaction(tx, None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(staker_wallet, hash, 80).await;

    // Stake the new validator's funds.
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .value(stake)
        .data(
            contracts::deposit::DEPOSIT
                .encode_input(&[
                    Token::Bytes(new_validator_key.node_public_key().as_bytes()),
                    Token::Bytes(
                        new_validator_key
                            .to_libp2p_keypair()
                            .public()
                            .to_peer_id()
                            .to_bytes(),
                    ),
                    Token::Bytes(deposit_signature_raw.to_compressed().to_vec()),
                    Token::Address(reward_address),
                ])
                .unwrap(),
        );
    let hash = staker_wallet
        .send_transaction(tx, None)
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(staker_wallet, hash, 80).await;
    assert_eq!(receipt.status.unwrap().as_u64(), 1);
    hash
}

#[allow(clippy::too_many_arguments)]
async fn deposit_v3_stake(
    network: &mut Network,
    control_wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    staker_wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    new_validator_key: SecretKey,
    stake: u128,
    reward_address: H160,
    signing_address: H160,
    deposit_signature_raw: &G2Projective,
) -> H256 {
    // Transfer the new validator enough ZIL to stake.
    let tx = TransactionRequest::pay(staker_wallet.address(), stake + 58190476400000000000);
    let hash = control_wallet
        .send_transaction(tx, None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(staker_wallet, hash, 80).await;

    // Stake the new validator's funds.
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .value(stake)
        .data(
            contracts::deposit_v3::DEPOSIT
                .encode_input(&[
                    Token::Bytes(new_validator_key.node_public_key().as_bytes()),
                    Token::Bytes(
                        new_validator_key
                            .to_libp2p_keypair()
                            .public()
                            .to_peer_id()
                            .to_bytes(),
                    ),
                    Token::Bytes(deposit_signature_raw.to_compressed().to_vec()),
                    Token::Address(reward_address),
                    Token::Address(signing_address),
                ])
                .unwrap(),
        );
    let hash = staker_wallet
        .send_transaction(tx, None)
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(staker_wallet, hash, 80).await;
    assert_eq!(receipt.status.unwrap().as_u64(), 1);
    hash
}

async fn current_epoch(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    block: Option<u64>,
) -> u64 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
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
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
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
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
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

async fn get_total_stake(wallet: &Wallet) -> u128 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .data(
            contracts::deposit::GET_TOTAL_STAKE
                .encode_input(&[])
                .unwrap(),
        );

    let stake = wallet.call(&tx.into(), None).await.unwrap();
    let stake = contracts::deposit::GET_TOTAL_STAKE
        .decode_output(&stake)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    stake.as_u128()
}

async fn get_stakers(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
) -> Vec<NodePublicKey> {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
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
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
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

async fn get_maximum_stakers(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
) -> u128 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .data(contracts::deposit::MAX_STAKERS.encode_input(&[]).unwrap());
    let deposit = wallet.call(&tx.into(), None).await.unwrap();

    let deposit = contracts::deposit::MAX_STAKERS
        .decode_output(&deposit)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    deposit.as_u128()
}

async fn get_blocks_per_epoch(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
) -> u64 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .data(
            contracts::deposit::BLOCKS_PER_EPOCH
                .encode_input(&[])
                .unwrap(),
        );
    let deposit = wallet.call(&tx.into(), None).await.unwrap();

    let deposit = contracts::deposit::BLOCKS_PER_EPOCH
        .decode_output(&deposit)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    deposit.as_u64()
}

async fn get_reward_address(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    staker: &NodePublicKey,
) -> H160 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .data(
            contracts::deposit::GET_REWARD_ADDRESS
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap(),
        );
    let return_value = wallet.call(&tx.into(), None).await.unwrap();
    contracts::deposit::GET_REWARD_ADDRESS
        .decode_output(&return_value)
        .unwrap()[0]
        .clone()
        .into_address()
        .unwrap()
}

async fn get_signing_address(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    staker: &NodePublicKey,
) -> H160 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .data(
            contracts::deposit_v3::GET_SIGNING_ADDRESS
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap(),
        );
    let return_value = wallet.call(&tx.into(), None).await.unwrap();
    contracts::deposit_v3::GET_SIGNING_ADDRESS
        .decode_output(&return_value)
        .unwrap()[0]
        .clone()
        .into_address()
        .unwrap()
}
#[allow(dead_code)]
async fn get_control_address(
    wallet: &SignerMiddleware<Provider<LocalRpcClient>, LocalWallet>,
    staker: &NodePublicKey,
) -> H160 {
    let tx = TransactionRequest::new()
        .to(H160(contract_addr::DEPOSIT_PROXY.into_array()))
        .data(
            contracts::deposit_v3::GET_CONTROL_ADDRESS
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap(),
        );
    let return_value = wallet.call(&tx.into(), None).await.unwrap();
    contracts::deposit_v3::GET_CONTROL_ADDRESS
        .decode_output(&return_value)
        .unwrap()[0]
        .clone()
        .into_address()
        .unwrap()
}

#[zilliqa_macros::test]
async fn deposit_storage_initially_set(mut network: Network) {
    let wallet = network.random_wallet().await;
    assert_eq!(
        get_minimum_deposit(&wallet).await,
        *network.nodes[0]
            .inner
            .lock()
            .unwrap()
            .config
            .consensus
            .minimum_stake
    );
    assert_eq!(
        get_maximum_stakers(&wallet).await,
        MAX_COMMITTEE_SIZE as u128
    );
    assert_eq!(
        get_blocks_per_epoch(&wallet).await,
        network.nodes[0]
            .inner
            .lock()
            .unwrap()
            .config
            .consensus
            .blocks_per_epoch
    );

    let stakers = get_stakers(&wallet).await;
    assert_eq!(
        stakers.len(),
        network.nodes[0]
            .inner
            .lock()
            .unwrap()
            .config
            .consensus
            .genesis_deposits
            .len()
    );

    // deposit contract gensis balance
    let total_stake = get_total_stake(&wallet).await;
    let deposit_balance = wallet
        .get_balance(H160(contract_addr::DEPOSIT_PROXY.into_array()), None)
        .await
        .unwrap()
        .as_u128();

    assert_ne!(deposit_balance, 0);
    assert_eq!(total_stake, deposit_balance);
}

#[zilliqa_macros::test]
async fn rewards_are_sent_to_reward_address_of_proposer(mut network: Network) {
    let wallet = network.random_wallet().await;

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);

    network.run_until_block(&wallet, 1.into(), 80).await;

    check_miner_got_reward(&wallet, 1).await;
}

#[zilliqa_macros::test(blocks_per_epoch = 2, deposit_v3_upgrade_block_height = 12)]
async fn validators_can_join_and_become_proposer(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // randomise the current epoch state and current leader
    let blocks_to_prerun = network.rng.lock().unwrap().gen_range(0..8);
    network
        .run_until_block(&wallet, blocks_to_prerun.into(), 100)
        .await;

    // First test joining deposit_v2
    let index = network.add_node();
    let new_validator_key = network.get_node_raw(index).secret_key;
    let reward_address = H160::random_using(&mut network.rng.lock().unwrap().deref_mut());

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);
    assert!(!stakers.contains(&new_validator_key.node_public_key()));

    let staker_wallet = network.wallet_of_node(index).await;
    let deposit_pop_signature = new_validator_key.pop_prove();

    let deposit_hash = deposit_stake(
        &mut network,
        &wallet,
        &staker_wallet,
        new_validator_key,
        32 * 10u128.pow(18),
        reward_address,
        &deposit_pop_signature.0,
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
    info!(deposit_block);

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

    // Now test joining deposit_v3
    let deposit_v3_deploy_block = 12;
    let index = network.add_node();
    let new_validator_priv_key = network.get_node_raw(index).secret_key;
    let new_validator_pub_key = new_validator_priv_key.node_public_key();
    let reward_address = H160::random_using(&mut network.rng.lock().unwrap().deref_mut());
    let signing_address = H160::random_using(&mut network.rng.lock().unwrap().deref_mut());

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 5);
    assert!(!stakers.contains(&new_validator_pub_key));

    let staker_wallet = network.wallet_of_node(index).await;
    let deposit_signature = new_validator_priv_key.deposit_auth_signature(
        network.shard_id,
        Address::from(staker_wallet.address().to_fixed_bytes()),
    );

    // Give new node time to catch up to block including deposit_v3 deployment
    network
        .run_until_block(&staker_wallet, deposit_v3_deploy_block.into(), 200)
        .await;

    let deposit_hash = deposit_v3_stake(
        &mut network,
        &wallet,
        &staker_wallet,
        new_validator_priv_key,
        32 * 10u128.pow(18),
        reward_address,
        signing_address,
        deposit_signature.as_raw_value(),
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
    info!(deposit_block);

    // Check set staker's addresses
    assert_eq!(
        get_reward_address(&staker_wallet, &new_validator_pub_key).await,
        reward_address
    );
    assert_eq!(
        get_signing_address(&staker_wallet, &new_validator_pub_key).await,
        signing_address
    );

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
                    assert_eq!(stakers.len(), 5);
                    assert!(!stakers.contains(&new_validator_priv_key.node_public_key()));
                    false // Keep running
                } else {
                    assert_eq!(stakers.len(), 6);
                    assert!(stakers.contains(&new_validator_priv_key.node_public_key()));
                    true
                }
            },
            200,
        )
        .await
        .unwrap();
}

#[zilliqa_macros::test(blocks_per_epoch = 2)]
async fn block_proposers_are_selected_proportionally_to_their_stake(mut network: Network) {
    // The starting configuration is 4 nodes with a stake of 32 ZIL each. We'll add a 5th node with a stake of 1024 ZIL
    // and check that it produces a statistically significant proportion of the subsequent blocks.

    let wallet = network.genesis_wallet().await;

    let index = network.add_node();
    let new_validator_key = network.get_node_raw(index).secret_key;
    let reward_address = H160::random_using(&mut network.rng.lock().unwrap().deref_mut());

    let staker_wallet = network.wallet_of_node(index).await;
    let deposit_signature = new_validator_key.pop_prove();

    deposit_stake(
        &mut network,
        &wallet,
        &staker_wallet,
        new_validator_key,
        1024 * 10u128.pow(18),
        reward_address,
        &deposit_signature.0,
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

    // The validator should leave the committee exactly two epochs after the one in which the withdrawal was made.
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
// * increase stake (deposit topup)
// * updating staker details (reward address, control address)
// * disallow access to callers other than the controlAddress
// * withdraw stake after 2 weeks (exercise the circular buffer logic or test it separately if difficult to do here)
