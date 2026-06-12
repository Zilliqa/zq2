use alloy::{
    eips::eip7702::Authorization,
    network::{TransactionBuilder, TransactionBuilder7702},
    primitives::{Bytes, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::SolCall,
};

use crate::{Network, deploy_contract, fund_wallet};

sol!(
    #[sol(rpc)]
    "tests/it/contracts/Counter.sol"
);

sol!(
    #[sol(rpc)]
    "tests/it/contracts/Bls12G1Add.sol"
);

// EIP-7702 — Alice (an EOA) signs an authorization that delegates her account's code to a
// `Counter` contract. Bob then submits a type-0x04 transaction containing that authorization
// alongside a call to Alice's address. After the transaction is mined:
//   - Alice's account code becomes the EIP-7702 delegation designator (`0xef0100 || target`).
//   - The call executes the `Counter` bytecode with Alice's account as the storage context, so
//     reading slot 0 of Alice's account returns the incremented counter value.
#[zilliqa_macros::test]
async fn eip_7702_delegation(mut network: Network) {
    let genesis = network.genesis_wallet().await;

    let (counter_addr, _) = deploy_contract(
        "tests/it/contracts/Counter.sol",
        "Counter",
        0,
        &genesis,
        &mut network,
    )
    .await;

    let alice_key = network.random_signing_key();

    let alice_signer = PrivateKeySigner::from_signing_key(alice_key);
    let alice_addr = alice_signer.address();

    let bob_wallet = network.random_wallet().await;

    // Bob pays for gas, so he needs funds. Alice does not — EIP-7702 lets the authority be a
    // pristine account.
    fund_wallet(&mut network, &genesis, &bob_wallet).await;

    let chain_id = bob_wallet.get_chain_id().await.unwrap();
    let gas_price = bob_wallet.get_gas_price().await.unwrap();

    // Alice's account has never sent a transaction so her nonce is 0; the auth `nonce` must
    // match this value at processing time.
    let auth = Authorization {
        chain_id: U256::from(chain_id),
        address: counter_addr,
        nonce: 0,
    };
    let signature = alice_signer.sign_hash_sync(&auth.signature_hash()).unwrap();
    let signed_auth = auth.into_signed(signature);

    // Bob calls `increment()` on Alice's address. With the delegation in place, the call runs
    // Counter's bytecode but stores into Alice's account.
    let calldata = Counter::incrementCall {}.abi_encode();
    let tx = TransactionRequest::default()
        .with_to(alice_addr)
        .with_input(calldata)
        .with_authorization_list(vec![signed_auth])
        .max_fee_per_gas(gas_price)
        .max_priority_fee_per_gas(gas_price)
        .gas_limit(500_000);

    let pending = bob_wallet.send_transaction(tx).await.unwrap();
    let receipt = network
        .run_until_receipt(&bob_wallet, pending.tx_hash(), 100)
        .await;
    assert!(receipt.status(), "EIP-7702 transaction should succeed");

    // Alice's code is now `0xef0100 || counter_addr` (23 bytes).
    let alice_code = bob_wallet.get_code_at(alice_addr).await.unwrap();
    assert_eq!(alice_code.len(), 23, "delegation designator is 23 bytes");
    assert_eq!(&alice_code[..3], &[0xef, 0x01, 0x00]);
    assert_eq!(&alice_code[3..], counter_addr.as_slice());

    // The increment ran with Alice's storage as `address(this)`: slot 0 should be 1.
    let storage_slot = bob_wallet
        .get_storage_at(alice_addr, U256::ZERO)
        .await
        .unwrap();
    assert_eq!(storage_slot, U256::from(1));

    // Reading via the Counter ABI bound to Alice's address goes through the delegation and
    // returns the same value.
    let counter_at_alice = Counter::new(alice_addr, &bob_wallet);
    let value = counter_at_alice.counter().call().await.unwrap();
    assert_eq!(value, U256::from(1));

    // The authorization bumped Alice's nonce to 1.
    let alice_nonce = bob_wallet.get_transaction_count(alice_addr).await.unwrap();
    assert_eq!(alice_nonce, 1);
}

// EIP-2537 — verify that the Pectra-only BLS12_G1ADD precompile (address `0x0b`) is reachable
// from Solidity via `staticcall`. Adding the point at infinity to itself must yield the point
// at infinity (an all-zero 128-byte buffer).
#[zilliqa_macros::test]
async fn eip_2537_bls12_g1_add(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (addr, _) = deploy_contract(
        "tests/it/contracts/Bls12G1Add.sol",
        "Bls12G1Add",
        0,
        &wallet,
        &mut network,
    )
    .await;

    // Two padded G1 points, each 128 bytes, both encoding the point at infinity.
    let input: Bytes = vec![0u8; 256].into();
    let bls = Bls12G1Add::new(addr, &wallet);
    let output = bls.addG1(input).call().await.unwrap();

    assert_eq!(output.len(), 128, "G1ADD output is one padded G1 point");
    assert!(
        output.iter().all(|b| *b == 0),
        "infinity + infinity = infinity"
    );
}
