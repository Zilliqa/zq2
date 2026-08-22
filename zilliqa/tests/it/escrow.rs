use crate::zil::{ToAddr, issue_create_transaction, zilliqa_account_with_funds_inner};
use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Address, U256, address},
    providers::Provider,
    rpc::types::TransactionRequest,
    sol,
};
use revm::primitives::ruint::aliases::B256;
use zilliqa::{api::types::zil::GetTxResponse, state::contract_addr::ESCROW_PROXY};

use crate::Network;

// Pre-computed dummy values
const PRIVATE_KEY: &str = "0x2f7d327e9eeb4d095962a8af74377b8a13a83274f97469d824de09d3fd9d9411";
const OLD_ACCOUNT: Address = address!("0x08bedb48fd607bf3aa43d89b103ba0310a05b5e1");
const NEW_ACCOUNT: Address = address!("0x4513F06070Bc8751fF9016e0d616Fa67C39Fd46e");
const CLAIM_PASS: &str = "0xcf1c94610c6ec6c6a492ec313237dd9455e13e9ce9c87db8a243e74a81a3c660b858c9572d6c7f62f52c6f6700e0b07808830adebdb710f2f53318cd101ff2d700cd99fc244453ac9b80f179191299e259ec40465f72f116fa8c5a3fa7454a13c7d3f91926d05641f9c577b1443c5c2eef7db0ce1c932e770421e0369a06e6edd7f5e1f72fe09d31a84b24e702459151b30a070fd55dbb7b616292acb434b003da5893b410e2324314c0fcd910252c7efe027a7826980da31c1a58b2993a6676c4b2adc01a971ef91a71d7579d013e0c7af6a44478d171029a01433bde1b4518f1fda4b21af861c5faece2a35785b4e2ccaec25011854e43daaa0506f5270777d33f8b6100000000000000000000000008bedb48fd607bf3aa43d89b103ba0310a05b5e10000000000000000000000004513f06070bc8751ff9016e0d616fa67c39fd46e00000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000000";
const CLAIM_FAIL: &str = "0xcf1c94610c6ec6c6a492ec313237dd9455e13e9ce9c87db8a243e74a81a3c660b858c9572d6c7f62f52c6f6700e0b07808830adebdb710f2f53318cd101ff2d700cd99fc244453ac9b80f179191299e259ec40465f72f116fa8c5a3fa7454a13c7d3f91926d05641f9c577b1443c5c2eef7db0ce1c932e770421e0369a06e6edd7f5e1f72fe09d31a84b24e702459151b30a070fd55dbb7b616292acb434b003da5893b410e2324314c0fcd910252c7efe027a7826980da31c1a58b2993a6676c4b2adc01a971ef91a71d7579d013e0c7af6a44478d171029a01433bde1b4518f1fda4b21af861c5faece2a35785b4e2ccaec25011854e43daaa0506f5270777d33f8b6100000000000000000000000008bedb48fd607bf3aa43d89b103ba0310a05b5e10000000000000000000000004513f06070bc8751ff9016e0d616fa67c39fd46e00000000000000000000000000000000000000000000000000000000000082bc0000000000000000000000000000000000000000000000000000000000000001";
// TODO: Keep in sync with latest escrow.sol
sol! {
    #[sol(rpc)]
    contract EscrowContract {
        function balanceOf(address addr) public view returns (uint256) {
        }
        function lodge() external payable {
        }
    }
}

// Primarily checks the ZKP verification path.
#[zilliqa_macros::test(zil_transfers_only_to_escrow)]
async fn lodge_and_claim_escrow(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let abi = EscrowContract::new(ESCROW_PROXY, &wallet);

    // Lodge amount via Scilla txn
    let secret_key =
        zilliqa::schnorr::SecretKey::from_slice(hex::decode(PRIVATE_KEY).unwrap().as_slice())
            .unwrap();
    let (old_secret_key, old_account) = zilliqa_account_with_funds_inner(
        &mut network,
        &wallet,
        58190476400000000000u128,
        secret_key,
    )
    .await;
    assert_eq!(old_account, OLD_ACCOUNT);

    let lodged_amount = 1u128;
    let response = issue_create_transaction(
        &wallet,
        &old_secret_key.public_key(),
        2_000_000_000_0,
        &mut network,
        &old_secret_key,
        1, // nonce
        ToAddr::Address(ESCROW_PROXY.into_array().into()),
        lodged_amount,
        50, // gas_limit in ScillaGas units — matches SCILLA_TRANSFER's flat-fee floor
        None,
        None,
    )
    .await
    .unwrap();
    let txn_hash: B256 = response["TranID"].as_str().unwrap().parse().unwrap();
    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> =
                    wallet.client().request("GetTransaction", [txn_hash]).await;
                response.is_ok()
            },
            100,
        )
        .await
        .unwrap();

    // Check lodged balance
    let lodgement = abi.balanceOf(OLD_ACCOUNT).call().await.unwrap();
    assert_ne!(lodgement, U256::ZERO);

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
