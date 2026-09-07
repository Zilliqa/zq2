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

// Precomputed dummy values
const _PRIVATE_KEY: &str = "0x4b288f64cd9e4f3e6f85b385aad3808821bbf1c8c8f8fa91ae090977e87c359b";
const OLD_ACCOUNT: Address = address!("0x680ffaeb3f8d74072d1a202d57ac8df8fada5fdf");
const NEW_ACCOUNT: Address = address!("0x4D88D8Fd2F3021B007d5a3a9e8DB3D05f9608D52");
const CLAIM_PASS: &str = "0xcf1c94610c43ac1e60ae4e157390e274353fea8421c8d76edd12028ca0cef7002302839626603087e521e38468ad9d0e842b2e2e46d27d6482dbb01079a7e68d2a4bda320c9a99f2ee0a687b2993533869adafe9f01bf5c8331c60e15be53bd86b8b15fd23c324cf9724bd17cd12952ff4beaff98ae3fd90c994d6139ef351ed6bc1ccf228c2ddcd0eb950fa1233a8a13b9ebabe0f8f3214473f43bd03f123bde7dc716426812ac7294ed63f500f72929d6784a6279b0b29474e163097103e207d734c51291d3c550a507b5f6642023fbf14166f333a90886ff94551282fffd4c4ff41722be767c1a4dc1a5c556d2e00da50b7c633376fbcd8c5bb77e00185a87d1107d8000000000000000000000000680ffaeb3f8d74072d1a202d57ac8df8fada5fdf0000000000000000000000004d88d8fd2f3021b007d5a3a9e8db3d05f9608d5200000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000001";
const CLAIM_FAIL: &str = "0xcf1c94610c43ac1e60ae4e157390e274353fea8421c8d76edd12028ca0cef7002302839626603087e521e38468ad9d0e842b2e2e46d27d6482dbb01079a7e68d2a4bda320c9a99f2ee0a687b2993533869adafe9f01bf5c8331c60e15be53bd86b8b15fd23c324cf9724bd17cd12952ff4beaff98ae3fd90c994d6139ef351ed6bc1ccf228c2ddcd0eb950fa1233a8a13b9ebabe0f8f3214473f43bd03f123bde7dc716426812ac7294ed63f500f72929d6784a6279b0b29474e163097103e207d734c51291d3c550a507b5f6642023fbf14166f333a90886ff94551282fffd4c4ff41722be767c1a4dc1a5c556d2e00da50b7c633376fbcd8c5bb77e00185a87d1107d8000000000000000000000000680ffaeb3f8d74072d1a202d57ac8df8fada5fdf0000000000000000000000004d88d8fd2f3021b007d5a3a9e8db3d05f9608d5200000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000000";

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
