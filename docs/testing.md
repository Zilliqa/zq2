# Testing and debugging hints

## RPC calls in tests

`tests/` uses an internal jsonrpsee client/server pair. You can see what this is doing with eg.:

```sh
export RUST_LOG=trace,zilliqa=warn,sled=warn
```

(we do this by exclusion since jsonrpsee has several crate names, but you could just as well enable `jsonrpsee-server`, `jsonrpsee_core` etc.)

And then:

```sh
cargo test eth::get_block_transaction_count
```
