use ethers::{prelude::{DeploymentTxFactory, CompilerInput}, providers::Middleware, types::TransactionRequest};
use ethers::abi::FunctionExt;
use ethers::solc::{EvmVersion};
use primitive_types::{H160, H256};

use crate::{random_wallet, Network};

use super::deploy_contract;

#[tokio::test]
async fn get_storage_at() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getstorageat.
    let hash = {
        let contract_source = b"// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.19;\ncontract Storage {\n    uint pos0;\n    mapping(address => uint) pos1;\n    constructor() {\n        pos0 = 1234;\n        pos1[msg.sender] = 5678;\n    }\n}\n";
        let mut contract_file = tempfile::Builder::new()
            .suffix(".sol")
            .tempfile()
            .unwrap();
        std::io::Write::write_all(&mut contract_file, contract_source).unwrap();
        let sc = ethers::solc::Solc::default();
        println!("sc args: {:?}", sc.args);
        //let aa = ethers::abi::Contract::
        //sc.args

        //let compiler_input = CompilerInput::new(contract_file.path().as_ref()).unwrap();
        let mut compiler_input = CompilerInput::new(contract_file.path()).unwrap();
        let compiler_input = compiler_input.first_mut().unwrap();
        compiler_input.settings.evm_version = Some(EvmVersion::Paris);

        let out = sc.compile::<CompilerInput>(compiler_input).unwrap();

        //let out = sc.compile_source(contract_file.path())
        //    .unwrap();
        println!("sc args: {:?}", sc.args);
        let contract = out
            .get(contract_file.path().to_str().unwrap(), "Storage")
            .unwrap();
        let abi = contract.abi.unwrap().clone();
        let bytecode = contract.bytecode().unwrap().clone();
        let factory = DeploymentTxFactory::new(abi, bytecode, wallet.clone());
        let deployment_tx = factory.deploy(()).unwrap().tx;
        let hash = wallet
            .send_transaction(deployment_tx, None)
            .await
            .unwrap()
            .tx_hash();
        network
            .run_until_async(
                |p| async move {
                    p.get_transaction_receipt(hash).await.unwrap().is_some()
                },
                10,
            )
            .await
            .unwrap();
        hash
    };

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();
    let contract_address = receipt.contract_address.unwrap();

    let value = provider
        .get_storage_at(contract_address, H256::zero(), None)
        .await
        .unwrap();
    assert_eq!(value, H256::from_low_u64_be(1234));

    // Calculate the storage position with keccak(LeftPad32(key, 0), LeftPad32(map position, 0))
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(receipt.from.as_bytes());
    bytes.extend_from_slice(&[0; 31]);
    bytes.push(1);
    let position = H256::from_slice(&ethers::utils::keccak256(bytes));
    let value = provider
        .get_storage_at(contract_address, position, None)
        .await
        .unwrap();
    println!("value: {:?}", value);
    assert_eq!(value, H256::from_low_u64_be(5678));
}

#[tokio::test]
async fn send_transaction() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    let to: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let tx = TransactionRequest::pay(to, 123);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    network
        .run_until_async(
            |p| async move { p.get_transaction_receipt(hash).await.unwrap().is_some() },
            10,
        )
        .await
        .unwrap();

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(receipt.to.unwrap(), to);
}

#[tokio::test]
async fn eth_call() {
    let mut network = Network::new(4);

    let provider = network.provider(0);
    let wallet = random_wallet(provider.clone());

    // Example from https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getstorageat.
    let (hash, abi) = deploy_contract!("contracts/SimpleContract.sol", "SimpleContract", wallet, network);

    let getter = abi.function("getInt256").unwrap();
    println!("getter: {:?}", getter);
    println!("getter: {:?}", getter.signature());
    println!("getter: {:?}", getter.inputs);
    println!("getter: {:?}", getter.abi_signature());
    println!("getter: {:?}", getter.short_signature());

    // Print the selector of the getter
    println!("getter: {:?}", getter.selector());


    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();
    let contract_address = receipt.contract_address.unwrap();

    //let tx = TransactionRequest::call(contract_address, getter.selector(), None);
    let mut tx = TransactionRequest::new();
    tx.to = Some(contract_address.into());
    tx.data = Some(getter.selector().into());
    //let tx = TypedTransaction::new(tx, None);

    let value = provider
        .call(&tx.into(), None)
        .await
        .unwrap();

    assert_eq!(H256::from_slice(value.as_ref()), H256::from_low_u64_be(99));
}
