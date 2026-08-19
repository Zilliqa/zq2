use crate::Network;
use alloy::primitives::{Address, U256, address};
use alloy::providers::{Provider, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::{hex, sol};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha2::{Digest as _, Sha256};
use zilliqa::schnorr;
use zilliqa::state::contract_addr::ESCROW_PROXY;

// Precomputed dummy values
const PRIVATE_KEY: &str = "0x4b288f64cd9e4f3e6f85b385aad3808821bbf1c8c8f8fa91ae090977e87c359b";
const KEY_ACCOUNT: Address = address!("0x19671A6De68FC73613B813902e351Ebd0b7B7408");
const NEW_ACCOUNT: Address = address!("0x4513F06070Bc8751fF9016e0d616Fa67C39Fd46e");

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
            uint256[3] calldata pubSignals
        ) public {
        }
    }
}

#[zilliqa_macros::test]
async fn lodge_escrow(mut network: Network) {
    let wallet = network
        .wallet_from_key(
            SigningKey::from_slice(
                hex::decode(PRIVATE_KEY) // hard-code private key for this test
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
        )
        .await;

    // prefund wallet
    let genesis_wallet = network.genesis_wallet().await;
    let tx = TransactionRequest::default()
        .to(wallet.default_signer_address())
        .value(U256::from(58190476400000000000u128));
    let tx_hash = *genesis_wallet.send_transaction(tx).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    assert!(receipt.status());

    // simulated balance
    let abi = EscrowContract::new(ESCROW_PROXY, &wallet);
    let balance = U256::from(123);

    // FIXME: Send via ZIL txn
    let tx_hash = *abi.lodge().value(balance).send().await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    assert!(receipt.status());

    // Check lodged balance
    let lodgement = abi
        .balanceOf(wallet.default_signer_address())
        .call()
        .await
        .unwrap();
    assert_eq!(lodgement, balance);
}

#[zilliqa_macros::test]
async fn claim_escrow(mut network: Network) {
    let schnorr_key = schnorr::SecretKey::from_slice(
        hex::decode(PRIVATE_KEY) // hard-code private key for this test
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let hashed = Sha256::digest(schnorr_key.public_key().to_encoded_point(true).as_bytes());
    let address = Address::from_slice(&hashed[12..]);

    println!("{address}");

    let wallet = network
        .wallet_from_key(
            SigningKey::from_slice(
                hex::decode(PRIVATE_KEY) // hard-code private key for this test
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
        )
        .await;

    // prefund wallet
    let genesis_wallet = network.genesis_wallet().await;
    let tx = TransactionRequest::default()
        .to(address)
        .value(U256::from(58190476400000000000u128));
    let tx_hash = *genesis_wallet.send_transaction(tx).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    assert!(receipt.status());

    // simulated balance
    let abi = EscrowContract::new(ESCROW_PROXY, &wallet);
    let balance = U256::from(123);

    // FIXME: Send via ZIL txn
    let tx_hash = *abi.lodge().value(balance).send().await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    assert!(receipt.status());

    // Check lodged balance
    let lodgement = abi.balanceOf(KEY_ACCOUNT).call().await.unwrap();
    assert_eq!(lodgement, balance);
}
