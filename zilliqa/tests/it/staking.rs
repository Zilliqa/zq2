use alloy::{
    eips::BlockId,
    primitives::{Address, TxHash, U256},
    providers::{Provider as _, WalletProvider},
    rpc::types::{TransactionInput, TransactionRequest},
};
use ethabi::Token;
use primitive_types::H160;
use rand::Rng;
use tracing::{info, trace};
use zilliqa::{
    contracts,
    crypto::{BlsSignature, NodePublicKey, SecretKey},
    message::MAX_COMMITTEE_SIZE,
    state::contract_addr,
};

use crate::{Network, Wallet, fund_wallet, get_reward_address, get_stakers};

async fn check_miner_got_reward(wallet: &Wallet, block: impl Into<BlockId> + Send + Sync) {
    let block = wallet.get_block(block.into()).await.unwrap().unwrap();
    let miner = block.header.beneficiary;
    let balance_before = wallet
        .get_balance(miner)
        .number(block.number() - 1)
        .await
        .unwrap();
    let balance_after = wallet
        .get_balance(miner)
        .number(block.number())
        .await
        .unwrap();

    assert!(balance_before < balance_after);
}

#[allow(clippy::too_many_arguments)]
async fn deposit_stake(
    network: &mut Network,
    control_wallet: &Wallet,
    staker_wallet: &Wallet,
    new_validator_key: SecretKey,
    stake: u128,
    reward_address: Address,
    signing_address: Address,
    deposit_signature: BlsSignature,
) -> (TxHash, u64) {
    // Transfer the new validator enough ZIL to stake.
    let tx = TransactionRequest::default()
        .to(staker_wallet.default_signer_address())
        .value(U256::from(stake + 58190476400000000000));
    let hash = *control_wallet.send_transaction(tx).await.unwrap().tx_hash();
    network.run_until_receipt(staker_wallet, &hash, 103).await;

    // Stake the new validator's funds.
    let data = contracts::deposit::DEPOSIT
        .encode_input(&[
            Token::Bytes(new_validator_key.node_public_key().as_bytes()),
            Token::Bytes(
                new_validator_key
                    .to_libp2p_keypair()
                    .public()
                    .to_peer_id()
                    .to_bytes(),
            ),
            Token::Bytes(deposit_signature.to_bytes()),
            Token::Address(reward_address.0.0.into()),
            Token::Address(signing_address.0.0.into()),
        ])
        .unwrap();
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .value(U256::from(stake))
        // Set a high gas limit manually, in case the gas estimate and transaction cross an epoch boundary, in which
        // case our estimate will be incorrect.
        .gas_limit(5_000_000)
        .input(TransactionInput::both(data.into()));

    let hash = *staker_wallet.send_transaction(tx).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(staker_wallet, &hash, 104).await;
    assert!(receipt.status());
    (hash, receipt.block_number.unwrap())
}

async fn current_epoch(wallet: &Wallet, block: Option<u64>) -> u64 {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::CURRENT_EPOCH
                .encode_input(&[])
                .unwrap()
                .into(),
        ));
    let response = wallet
        .call(tx)
        .block(block.map_or(BlockId::pending(), BlockId::number))
        .await
        .unwrap();
    let epoch = contracts::deposit::CURRENT_EPOCH
        .decode_output(&response)
        .unwrap()
        .remove(0)
        .into_uint()
        .unwrap()
        .as_u64();

    // when block.is_none(), the call goes to the pending block, which is the next block
    let current_block = block.unwrap_or(wallet.get_block_number().await.unwrap() + 1);

    // Sanity check that epochs are calculated correctly (assuming `blocks_per_epoch = 2`).
    assert_eq!(epoch, current_block / 2, "{epoch} :: {current_block}");

    epoch
}

async fn unstake_amount(
    network: &mut Network,
    blskey: &NodePublicKey,
    control_wallet: &Wallet,
    amount: u128,
) -> (TxHash, u64) {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::UNSTAKE
                .encode_input(&[Token::Bytes(blskey.as_bytes()), Token::Uint(amount.into())])
                .unwrap()
                .into(),
        ))
        .gas_limit(10000000); // TODO: Why needed?
    let hash = *control_wallet.send_transaction(tx).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(control_wallet, &hash, 200).await;
    assert!(receipt.status());
    (hash, receipt.block_number.unwrap())
}

async fn get_stake(wallet: &Wallet, staker: &NodePublicKey) -> u128 {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::GET_STAKE
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap()
                .into(),
        ));
    let output = wallet.call(tx).await.unwrap();

    contracts::deposit::GET_STAKE
        .decode_output(&output)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap()
        .as_u128()
}

async fn get_total_stake(wallet: &Wallet) -> u128 {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::GET_TOTAL_STAKE
                .encode_input(&[])
                .unwrap()
                .into(),
        ));

    let stake = wallet.call(tx).await.unwrap();
    let stake = contracts::deposit::GET_TOTAL_STAKE
        .decode_output(&stake)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    stake.as_u128()
}

async fn get_minimum_deposit(wallet: &Wallet) -> u128 {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::MIN_DEPOSIT
                .encode_input(&[])
                .unwrap()
                .into(),
        ));
    let deposit = wallet.call(tx).await.unwrap();

    let deposit = contracts::deposit::MIN_DEPOSIT
        .decode_output(&deposit)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    deposit.as_u128()
}

async fn get_maximum_stakers(wallet: &Wallet) -> u128 {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::MAX_STAKERS
                .encode_input(&[])
                .unwrap()
                .into(),
        ));
    let deposit = wallet.call(tx).await.unwrap();

    let deposit = contracts::deposit::MAX_STAKERS
        .decode_output(&deposit)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    deposit.as_u128()
}

async fn get_blocks_per_epoch(wallet: &Wallet) -> u64 {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::BLOCKS_PER_EPOCH
                .encode_input(&[])
                .unwrap()
                .into(),
        ));
    let deposit = wallet.call(tx).await.unwrap();

    let deposit = contracts::deposit::BLOCKS_PER_EPOCH
        .decode_output(&deposit)
        .unwrap()[0]
        .clone()
        .into_uint()
        .unwrap();

    deposit.as_u64()
}

async fn get_signing_address(wallet: &Wallet, staker: &NodePublicKey) -> Address {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit::GET_SIGNING_ADDRESS
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap()
                .into(),
        ));
    let return_value = wallet.call(tx).await.unwrap();
    contracts::deposit::GET_SIGNING_ADDRESS
        .decode_output(&return_value)
        .unwrap()[0]
        .clone()
        .into_address()
        .unwrap()
        .0
        .into()
}

#[allow(dead_code)]
async fn get_control_address(wallet: &Wallet, staker: &NodePublicKey) -> H160 {
    let tx = TransactionRequest::default()
        .to(contract_addr::DEPOSIT_PROXY)
        .input(TransactionInput::both(
            contracts::deposit_v3::GET_CONTROL_ADDRESS
                .encode_input(&[Token::Bytes(staker.as_bytes())])
                .unwrap()
                .into(),
        ));
    let return_value = wallet.call(tx).await.unwrap();
    contracts::deposit_v3::GET_CONTROL_ADDRESS
        .decode_output(&return_value)
        .unwrap()[0]
        .clone()
        .into_address()
        .unwrap()
        .0
        .into()
}

#[zilliqa_macros::test]
async fn deposit_storage_initially_set(mut network: Network) {
    let wallet = network.random_wallet().await;
    assert_eq!(
        get_minimum_deposit(&wallet).await,
        *network.nodes[0].inner.config.consensus.minimum_stake
    );
    assert_eq!(
        get_maximum_stakers(&wallet).await,
        MAX_COMMITTEE_SIZE as u128
    );
    assert_eq!(
        get_blocks_per_epoch(&wallet).await,
        network.nodes[0].inner.config.consensus.blocks_per_epoch
    );

    let stakers = get_stakers(&wallet).await;
    assert_eq!(
        stakers.len(),
        network.nodes[0]
            .inner
            .config
            .consensus
            .genesis_deposits
            .len()
    );

    // deposit contract gensis balance
    let total_stake = U256::from(get_total_stake(&wallet).await);
    let deposit_balance = wallet
        .get_balance(contract_addr::DEPOSIT_PROXY)
        .await
        .unwrap();

    assert_ne!(deposit_balance, 0);
    assert_eq!(total_stake, deposit_balance);
}

#[zilliqa_macros::test]
async fn rewards_are_sent_to_reward_address_of_proposer(mut network: Network) {
    let wallet = network.random_wallet().await;

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);

    network.run_until_block_finalized(2, 80).await.unwrap();

    check_miner_got_reward(&wallet, 1).await;
}

// #[zilliqa_macros::test(blocks_per_epoch = 2, deposit_v3_upgrade_block_height = 24)]
#[zilliqa_macros::test(blocks_per_epoch = 2)]
async fn validators_can_join_and_become_proposer(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // randomise the current epoch state and current leader
    let start_at = network.rng.lock().unwrap().gen_range(1..4);
    network
        .run_until_block_finalized(start_at, 400)
        .await
        .unwrap();

    // Join a new validator
    let index = network.add_node();
    let new_validator_priv_key = network.get_node_raw(index).secret_key;
    let new_validator_pub_key = new_validator_priv_key.node_public_key();
    let reward_address = Address::random();
    let signing_address = Address::random();

    let stakers = get_stakers(&wallet).await;
    assert_eq!(stakers.len(), 4);
    assert!(!stakers.contains(&new_validator_pub_key));

    let staker_wallet = network.wallet_of_node(index).await;
    let deposit_signature = new_validator_priv_key
        .deposit_auth_signature(network.shard_id, staker_wallet.default_signer_address());

    // Give new node time to catch up
    network.run_until_synced(index).await;

    let (_deposit_hash, deposit_block) = deposit_stake(
        &mut network,
        &wallet,
        &staker_wallet,
        new_validator_priv_key,
        32 * 10u128.pow(18),
        reward_address,
        signing_address,
        deposit_signature,
    )
    .await;

    // wait until deposit block is finalised
    network
        .run_until_block_finalized(deposit_block, 100)
        .await
        .unwrap();

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
                    assert_eq!(stakers.len(), 4, "{stakers:?}");
                    assert!(!stakers.contains(&new_validator_priv_key.node_public_key()));
                    false // Keep running
                } else {
                    assert_eq!(stakers.len(), 5, "{stakers:?}");
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
    let reward_address = Address::random();
    let signing_address = Address::random();

    let staker_wallet = network.wallet_of_node(index).await;
    let deposit_signature = new_validator_key
        .deposit_auth_signature(network.shard_id, staker_wallet.default_signer_address());

    network.run_until_synced(index).await;
    let (_, deposit_height) = deposit_stake(
        &mut network,
        &wallet,
        &staker_wallet,
        new_validator_key,
        1024 * 10u128.pow(18),
        reward_address,
        signing_address,
        deposit_signature,
    )
    .await;
    network
        .run_until_block_finalized(deposit_height, 100)
        .await
        .unwrap();

    // Start counting at the point where the new validator becomes a block proposer. This guarantees it is now part of
    // the consensus committee.
    network
        .run_until_async(
            || async {
                wallet
                    .get_block(BlockId::latest())
                    .await
                    .unwrap()
                    .unwrap()
                    .header
                    .beneficiary
                    == reward_address
            },
            1000,
        )
        .await
        .unwrap();

    let current_block = wallet.get_block_number().await.unwrap();
    info!(current_block, ?reward_address, "deposit staked");
    network
        .run_until_async(
            || async { wallet.get_block_number().await.unwrap() >= current_block + 20 },
            1000,
        )
        .await
        .unwrap();

    let mut proposers = vec![];
    for b in current_block..=(current_block + 20) {
        let block = wallet.get_block(BlockId::number(b)).await.unwrap().unwrap();
        proposers.push(block.header.beneficiary);
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
    let start_at = network.rng.lock().unwrap().gen_range(1..6);
    network
        .run_until_block_finalized(start_at, 400)
        .await
        .unwrap();

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
    assert_eq!(stakers.len(), 4, "{stakers:?}");
    assert!(stakers.contains(&validator_blskey));

    // unstake validator's entire stake
    let stake = get_stake(&wallet, &validator_blskey).await;
    let (_unstake_hash, unstake_block) = unstake_amount(
        &mut network,
        &validator_blskey,
        &validator_control_wallet,
        stake,
    )
    .await;

    // wait until unstake block is finalised
    network
        .run_until_block_finalized(unstake_block, 100)
        .await
        .unwrap();

    // The validator should leave the committee exactly two epochs after the one in which the withdrawal was made.
    let unstake_epoch = current_epoch(&wallet, Some(unstake_block)).await;
    network
        .run_until_async(
            || async {
                let should_be_in_committee = current_epoch(&wallet, None).await < unstake_epoch + 2;

                let stakers = get_stakers(&wallet).await;
                if should_be_in_committee {
                    assert_eq!(stakers.len(), 4, "{stakers:?}");
                    assert!(stakers.contains(&validator_blskey));
                    false // Keep running
                } else {
                    assert_eq!(stakers.len(), 3);
                    assert!(!stakers.contains(&validator_blskey));
                    true
                }
            },
            400,
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
                wallet.get_block_number().await.unwrap() >= unstake_block + 15
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
