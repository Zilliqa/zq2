use crate::Network;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256, address};
use alloy::providers::{Provider, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::{hex, sol};
use k256::ecdsa::SigningKey;
use zilliqa::state::contract_addr::ESCROW_PROXY;

// Precomputed dummy values
const PRIVATE_KEY: &str = "0x4b288f64cd9e4f3e6f85b385aad3808821bbf1c8c8f8fa91ae090977e87c359b";
const OLD_ACCOUNT: Address = address!("0x680ffaeb3f8d74072d1a202d57ac8df8fada5fdf");
const NEW_ACCOUNT: Address = address!("0x4513F06070Bc8751fF9016e0d616Fa67C39Fd46e");
const CLAIM_PASS: &str = "0xa6e0ecc11048369f481676b0c6b02ba0860600fbcc5392bea0cadc57edfbc1910d527e6b285c7567f3d3e0421a920f3c5bc16f93a63fff3be906a10fb0676d38e1223282028f963d5ffe7be012ba5498d17ed349fd35803613fa50b4595e329adda06eec00b436c9490ed5b8bc08465c4a6714f42f8675cbbd91c42186238d9f9a8c097a272357a64bd2b88c759335a2428d970720f46e5e4194bbe7db414224c656b29b2cf23ce05097b8809352179aa268f09197d20f6a53a8e06a1386d93ee79c2ff72467905a3f6fbd466b29fadd9af55f451546272f8f28821ae916975a95fde39418a5d363f89d6b20943fbf6633c397deab55f3657cb4a0c38d7c677493c3334e000000000000000000000000680ffaeb3f8d74072d1a202d57ac8df8fada5fdf0000000000000000000000004513f06070bc8751ff9016e0d616fa67c39fd46e00000000000000000000000000000000000000000000000000000000000082bc";
const CLAIM_FAIL: &str = "0xa6e0ecc11048369f481676b0c6b02ba0860600fbcc5392bea0cadc57edfbc1910d527e6b285c7567f3d3e0421a920f3c5bc16f93a63fff3be906a10fb0676d38e1223282028f963d5ffe7be012ba5498d17ed349fd35803613fa50b4595e329adda06eec00b436c9490ed5b8bc08465c4a6714f42f8675cbbd91c42186238d9f9a8c097a272357a64bd2b88c759335a2428d970720f46e5e4194bbe7db414224c656b29b2cf23ce05097b8809352179aa268f09197d20f6a53a8e06a1386d93ee79c2ff72467905a3f6fbd466b29fadd9af55f451546272f8f28821ae916975a95fde39418a5d363f89d6b20943fbf6633c397deab55f3657cb4a0c38d7c677493c3334e000000000000000000000000680ffaeb3f8d74072d1a202d57ac8df8fada5fdf0000000000000000000000004513f06070bc8751ff9016e0d616fa67c39fd46f00000000000000000000000000000000000000000000000000000000000082bc";

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

// Checks that the lodgement path works
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

// Primarily checks the ZKP verification path.
#[zilliqa_macros::test]
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
