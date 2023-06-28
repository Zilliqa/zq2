use ethabi::RawLog;
use ethers::{providers::Middleware, types::TransactionRequest};
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};

use crate::{deploy_contract, Network};

#[zilliqa_macros::test]
async fn get_contract_creator(mut network: Network<'_>) {
    let wallet = network.random_wallet();

    let (hash, abi) = deploy_contract!("contracts/ContractCreator.sol", "Creator", wallet, network);

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();

    #[derive(Debug, Serialize, Deserialize)]
    struct ContractCreator {
        hash: H256,
        creator: H160,
    }

    // First verify the creator of the `Creator` contract is correct. This should be the same as the `from` address in
    // the receipt.
    let response: ContractCreator = wallet
        .provider()
        .request("ots_getContractCreator", [contract_address])
        .await
        .unwrap();
    assert_eq!(response.hash, hash);
    assert_eq!(response.creator, receipt.from);

    // Now call the `Creator` contract to deploy the `CreateMe` contract.
    let call_tx = TransactionRequest::new()
        .to(contract_address)
        .data(abi.function("create").unwrap().encode_input(&[]).unwrap());

    let hash = wallet
        .send_transaction(call_tx, None)
        .await
        .unwrap()
        .tx_hash();

    network
        .run_until_async(
            || async {
                wallet
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let log = receipt.logs[0].clone();
    let log: RawLog = (log.topics, log.data.to_vec()).into();
    let log = abi.event("Created").unwrap().parse_log_whole(log).unwrap();

    let created_address = log.params[0].value.clone().into_address().unwrap();

    // Verify the creator of the `CreateMe` contract is the `Creator` contract.
    let response: ContractCreator = wallet
        .provider()
        .request("ots_getContractCreator", [created_address])
        .await
        .unwrap();
    assert_eq!(response.hash, hash);
    assert_eq!(response.creator, contract_address);
}
