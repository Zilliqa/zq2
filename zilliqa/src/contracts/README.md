## Compiling

All contracts currently are compiled into `./compiled.json`.

You'll first need to pull the OpenZeppelin modules:

```sh
git clone https://github.com/OpenZeppelin/openzeppelin-contracts.git vendor/openzeppelin-contracts
git clone https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git vendor/openzeppelin-contracts-upgradeable
```

Then compile with Foundry via Rust tests:

```sh
ZQ_CONTRACT_TEST_BLESS=1 cargo test --features test_contract_bytecode -- contracts::tests::compile_all
```