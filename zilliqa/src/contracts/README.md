## Compiling

All contracts currently are compiled into `./compiled.json`.

You'll first need to pull the OpenZeppelin modules:

```sh
git submodule update --init
```

Then compile with `solc`:

```sh
ZQ_CONTRACT_TEST_BLESS=1 cargo test --features test_contract_bytecode -- contracts::tests::compile_all
```