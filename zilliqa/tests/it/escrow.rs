use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Address, B256, U256, address},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
    sol,
    sol_types::{SolCall, SolValue},
};
use k256::ecdsa::SigningKey;
use zilliqa::state::contract_addr::{ESCROW_MINTABLE_PROXY, ESCROW_PROXY};

use crate::{Network, compile_contract};

// Precomputed dummy values
const PRIVATE_KEY: &str = "0x4b288f64cd9e4f3e6f85b385aad3808821bbf1c8c8f8fa91ae090977e87c359b";
const OLD_ACCOUNT: Address = address!("0x680ffaeb3f8d74072d1a202d57ac8df8fada5fdf");
const NEW_ACCOUNT: Address = address!("0x4513F06070Bc8751fF9016e0d616Fa67C39Fd46e");
const CLAIM_PASS: &str = "0xcf1c94612899d74d7a5c25b134356691b8819fc728d4b00a10186d4f9623fb610006817f2687b2f4acb690eb7eed368a40398cf0d1b3c993a652baa5482185fc757a8a91179ee9ea9333a002f5becd4be59aca66e6200339aa17b524b4f54e1dd937f19f1b916262a768b4253ceb90d29a6ec673537a2cb7e4cb16596e65979e39bd010917ec8bc7af642d2ffee406d31c1a8830a9d80e3fe34217b3b45163143f69bcca099cab798be1d26380f51961bf62f27f253b888b6ddce561d186a61bf85c5c6629c91ba363a58f7b196f18af106398e2b99ba1ea66c8ee09f30638dff72a507623e37e4b0d414e47f88f519dee0bcab11d773bde66ed3651504c53b387260294000000000000000000000000680ffaeb3f8d74072d1a202d57ac8df8fada5fdf0000000000000000000000004513f06070bc8751ff9016e0d616fa67c39fd46e00000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000001";
const CLAIM_FAIL: &str = "0xcf1c94612899d74d7a5c25b134356691b8819fc728d4b00a10186d4f9623fb610006817f2687b2f4acb690eb7eed368a40398cf0d1b3c993a652baa5482185fc757a8a91179ee9ea9333a002f5becd4be59aca66e6200339aa17b524b4f54e1dd937f19f1b916262a768b4253ceb90d29a6ec673537a2cb7e4cb16596e65979e39bd010917ec8bc7af642d2ffee406d31c1a8830a9d80e3fe34217b3b45163143f69bcca099cab798be1d26380f51961bf62f27f253b888b6ddce561d186a61bf85c5c6629c91ba363a58f7b196f18af106398e2b99ba1ea66c8ee09f30638dff72a507623e37e4b0d414e47f88f519dee0bcab11d773bde66ed3651504c53b387260294000000000000000000000000680ffaeb3f8d74072d1a202d57ac8df8fada5fdf0000000000000000000000004513f06070bc8751ff9016e0d616fa67c39fd46e00000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000000";

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

// Keep in sync with escrow_mintable_v1.sol
sol! {
    #[sol(rpc)]
    contract EscrowMintable {
        function deploy(bytes32 salt, bytes calldata initCode) external returns (address token);
        function lodge(address token, address[] calldata users, uint256[] calldata amounts) external;
        function balanceOf(address token, address user) public view returns (uint256);
        function register(address token) external;
        function setAdmin(address newAdmin) external;
        function isDeployed(address token) public view returns (bool);
        function isRegistered(address token) public view returns (bool);
        function tokens() public view returns (address[] memory);
        function admin() public view returns (address);
    }
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/EscrowMintableToken.sol",
);

// Anyone may CREATE2-deploy a token through the mintable escrow, but only the admin (the genesis
// wallet on test chains) registers it for lodging; lodging, minting and admin changes stay closed
// to wallets. The lodge/claim path runs at the state level in `exec.rs` tests, since lodging is a
// system operation driven by a fork schedule.
#[zilliqa_macros::test]
async fn mintable_escrow_deploys_tokens_by_create2(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let escrow = EscrowMintable::new(ESCROW_MINTABLE_PROXY, &wallet);
    assert_eq!(
        escrow.admin().call().await.unwrap(),
        wallet.default_signer_address()
    );

    let (_, bytecode) = compile_contract(
        "tests/it/contracts/EscrowMintableToken.sol",
        "EscrowMintableToken",
    );
    let mut init_code = bytecode.to_vec();
    init_code.extend(ESCROW_MINTABLE_PROXY.abi_encode());
    let salt = B256::repeat_byte(1);
    let expected = ESCROW_MINTABLE_PROXY.create2_from_code(salt, &init_code);

    // Raw call: the `sol!` instance's own `deploy` shadows the contract function.
    let input = EscrowMintable::deployCall {
        salt,
        initCode: init_code.into(),
    }
    .abi_encode();

    // A funded stranger deploys; the token exists but is not lodgeable. Gas estimation caps
    // the limit by balance, and CREATE2 swallows an inner out-of-gas, so fund generously.
    let stranger = network.random_wallet().await;
    let tx = TransactionRequest::default()
        .with_to(stranger.default_signer_address())
        .with_value(U256::from(1_000_000_000_000_000_000_000u128));
    let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();
    // Each wallet talks to its own node; the stranger's must see the funds before estimating.
    network.run_until_receipt(&stranger, &tx_hash, 100).await;
    let tx = TransactionRequest::default()
        .with_to(ESCROW_MINTABLE_PROXY)
        .with_input(input);
    let tx_hash = *stranger.send_transaction(tx).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&stranger, &tx_hash, 100).await;
    assert!(receipt.status());
    assert!(escrow.isDeployed(expected).call().await.unwrap());
    assert!(!escrow.isRegistered(expected).call().await.unwrap());

    // Only the admin registers it.
    let stranger_escrow = EscrowMintable::new(ESCROW_MINTABLE_PROXY, &stranger);
    assert!(
        stranger_escrow.register(expected).send().await.is_err(),
        "register is admin-only"
    );
    let tx_hash = *escrow.register(expected).send().await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    assert!(receipt.status());
    assert!(escrow.isRegistered(expected).call().await.unwrap());
    assert_eq!(escrow.tokens().call().await.unwrap(), vec![expected]);

    assert!(
        escrow
            .setAdmin(stranger.default_signer_address())
            .send()
            .await
            .is_err(),
        "setAdmin is system-only"
    );
    let token = EscrowMintableToken::new(expected, &wallet);
    assert_eq!(token.escrow().call().await.unwrap(), ESCROW_MINTABLE_PROXY);

    let me = wallet.default_signer_address();
    assert!(
        escrow
            .lodge(expected, vec![me], vec![U256::from(1)])
            .send()
            .await
            .is_err(),
        "lodge is system-only"
    );
    assert!(
        token.mint(me, U256::from(1)).send().await.is_err(),
        "only the escrow may mint"
    );
    assert_eq!(
        escrow.balanceOf(expected, me).call().await.unwrap(),
        U256::ZERO
    );
    assert_eq!(token.balanceOf(me).call().await.unwrap(), U256::ZERO);
}
