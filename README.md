# Zilliqa 2.0 - The next evolution of Zilliqa

## Running a Node

To start a node you need to pass a private key as a command line parameter.
This will be interpreted as both a BLS private key and a libp2p secp256k1 private key (of course the corresponding public keys will be different).

You will need to start at least 4 nodes before the network will begin to make progress.

### Example invocations for a network with 4 nodes

```
cargo run -- 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227
cargo run -- 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e
cargo run -- 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364
cargo run -- db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a
```

You may also want to set `RUST_LOG=zilliqa=trace` to see the most detailed level of logs.
