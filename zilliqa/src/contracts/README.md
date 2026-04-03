## Compiling

Contracts are compiled into separate JSON files per contract group:

- `compiled_legacy.json` — legacy contracts (deposit_v1 through v7, shard, intershard_bridge, shard_registry, ERC1967Proxy). **Do not recompile.** These were originally compiled with `foundry-compilers = 0.14.1` and recompiling with the current version will produce different bytecode. The `compile_legacy` test is kept only for compatibility reasons and should never be run.
- `compiled_deposit_v8.json` — deposit_v8 contract.

Each new contract should get its own `compiled_<name>.json` file, a corresponding `const COMPILED_<NAME>` in `mod.rs`, and a test function gated by `ZQ_COMPILE_CONTRACTS`.

**Important:** Compiled bytecode depends on the exact version of the `foundry-compilers` crate (currently `0.19.14`). You should only compile a newly added contract once to generate its JSON file. If the `foundry-compilers` crate version changes, the bytecode output is likely to differ, which will break verification tests for previously compiled contracts. Do not re-bless existing contracts after a crate upgrade unless you intentionally want to change the on-chain bytecode.

### Prerequisites

Pull the OpenZeppelin modules:

```sh
git submodule update --init --recursive
```

### Compiling contracts

By default, no contracts are compiled. Use `ZQ_COMPILE_CONTRACTS` to specify which contract groups to compile (comma-separated), or `all` for everything.

**Compile deposit_v8:**

```sh
ZQ_COMPILE_CONTRACTS=deposit_v8 ZQ_CONTRACT_TEST_BLESS=1 cargo test --features test_contract_bytecode -- contracts::tests::compile_deposit_v8
```

**Verify compiled output matches (without blessing):**

```sh
ZQ_COMPILE_CONTRACTS=deposit_v8 cargo test --features test_contract_bytecode -- contracts::tests::compile_deposit_v8
```

Without `ZQ_CONTRACT_TEST_BLESS`, the test will recompile and assert the output matches the committed JSON file.

### Adding a new contract

1. Create `src/contracts/<name>.sol`.
2. Add `const COMPILED_<NAME>: &str = include_str!("compiled_<name>.json");` in `mod.rs`.
3. Add a module in `mod.rs` using `contract_from(COMPILED_<NAME>, ...)`.
4. Add a `compile_<name>` test function following the existing pattern, gated by `should_compile("<name>")`.
5. Run `ZQ_COMPILE_CONTRACTS=<name> ZQ_CONTRACT_TEST_BLESS=1 cargo test --features test_contract_bytecode -- contracts::tests::compile_<name>` to generate the compiled JSON.
6. Commit the new `.sol` and `.json` files.

### Legacy contracts (do not use)

The `compile_legacy` test exists only for historical compatibility. **Do not run it.** The legacy contracts in `compiled_legacy.json` were compiled with `foundry-compilers = 0.14.1` and cannot be reproduced with the current crate version.

## Run Solidity tests

```sh
    forge test -C zilliqa/src/contracts/tests
```