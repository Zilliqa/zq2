use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Address, U256, address},
    providers::Provider,
    rpc::types::TransactionRequest,
    sol,
};
use zilliqa::state::contract_addr::ESCROW_PROXY;

use crate::Network;

// Real production-ceremony proof (final.zkey sha256 87191dc2…), generated from the PUBLIC all-zero
// BIP-39 test vector ("abandon…about") on the hardened Ledger path m/44'/313'/0'/0'/0'.
// OLD_ACCOUNT is the Zilliqa (SHA-256[-20:]) address that seed derives; domain=33468 = eth_chain_id_default().
const OLD_ACCOUNT: Address = address!("0xb413df42a4e2d5236fe1b914a21c354eb86f133c");
const NEW_ACCOUNT: Address = address!("0x4D88D8Fd2F3021B007d5a3a9e8DB3D05f9608D52");
const CLAIM_PASS: &str = "0xcf1c946114c9eedcb5f1610696fc1a6e6e218f02991d89d4654cd6648d174d7efba7388f14a1c951c6052b0934975255b2e80f0e9bf5082baf8cea55364e02de57063dd525fde970e236b2cfdee6d3c4cff9567cb723f1673fe3eca88d4619bb652c262b29cae0f48d9bfbb92efdcfab45e65ae34acbb1fdee2a41a24d636ccc4c4d4a3000cd58bf905ef79d38b27e163907e13d4533c073953903e8f66f02f2b3690920028a2bc140725a931657db5ad75c74fad2c5abe75b9f39aa23dc75e436ad9b1b221e117218e4f526f7e2a12309a11af2a4e7614ad8a13e2ff270f51c96a63ba104265394cd693798f282d07fc127d88908089848c66e249888cc50ce6ed34bb4000000000000000000000000b413df42a4e2d5236fe1b914a21c354eb86f133c0000000000000000000000004d88d8fd2f3021b007d5a3a9e8db3d05f9608d5200000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000001";
// Same valid proof, but with the isHardened public input tampered 1 -> 0, so verification must fail.
const CLAIM_FAIL: &str = "0xcf1c946114c9eedcb5f1610696fc1a6e6e218f02991d89d4654cd6648d174d7efba7388f14a1c951c6052b0934975255b2e80f0e9bf5082baf8cea55364e02de57063dd525fde970e236b2cfdee6d3c4cff9567cb723f1673fe3eca88d4619bb652c262b29cae0f48d9bfbb92efdcfab45e65ae34acbb1fdee2a41a24d636ccc4c4d4a3000cd58bf905ef79d38b27e163907e13d4533c073953903e8f66f02f2b3690920028a2bc140725a931657db5ad75c74fad2c5abe75b9f39aa23dc75e436ad9b1b221e117218e4f526f7e2a12309a11af2a4e7614ad8a13e2ff270f51c96a63ba104265394cd693798f282d07fc127d88908089848c66e249888cc50ce6ed34bb4000000000000000000000000b413df42a4e2d5236fe1b914a21c354eb86f133c0000000000000000000000004d88d8fd2f3021b007d5a3a9e8db3d05f9608d5200000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000000";

// TODO: Keep in sync with latest escrow.sol
sol! {
    #[sol(rpc)]
    contract EscrowContract {
        function balanceOf(address addr) public view returns (uint256) {
        }
        function lodge() external payable {
        }
        function claim(
            uint256[2] calldata pA,
            uint256[2][2] calldata pB,
            uint256[2] calldata pC,
            uint256[4] calldata pubSignals
        ) public {
        }
    }
}

// Checks that the lodgement path works
#[zilliqa_macros::test(ignore)]
async fn evm_lodge_escrow_is_blocked(mut network: Network) {
    let genesis_wallet = network.genesis_wallet().await;
    let abi = EscrowContract::new(ESCROW_PROXY, &genesis_wallet);
    let balance = U256::from(123);

    // FIXME: Send via ZIL txn
    let _res = abi.lodge().value(balance).send().await.unwrap();
    // assert!(res.is_err());
}

// Primarily checks the ZKP verification path.
#[zilliqa_macros::test(ignore)]
async fn claim_escrow(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let abi = EscrowContract::new(ESCROW_PROXY, &wallet);

    // TODO: Check lodged balance
    let lodgement = abi.balanceOf(OLD_ACCOUNT).call().await.unwrap();
    // assert_ne!(lodgement, U256::ZERO);

    // Send failed claim
    let tx = TransactionRequest::default()
        .with_to(ESCROW_PROXY)
        .with_input(hex::decode(CLAIM_FAIL).unwrap());
    let tx_hash = wallet.send_transaction(tx).await;
    assert!(tx_hash.is_err());

    // Send valid claim
    let tx = TransactionRequest::default()
        .with_to(ESCROW_PROXY)
        .with_input(hex::decode(CLAIM_PASS).unwrap());
    let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    assert!(receipt.status());

    // Check lodged balance
    let balance = abi.balanceOf(OLD_ACCOUNT).call().await.unwrap();
    assert_eq!(balance, U256::ZERO);

    // Check the new balance
    let transfer = wallet.get_balance(NEW_ACCOUNT).await.unwrap();
    assert_eq!(lodgement, transfer);
}
