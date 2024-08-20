# Zilliqa 2.0 - The next evolution of Zilliqa

Further documentation can be found in the `docs/` directory, for Zilliqa 2 itself, and in `z2/docs` for the `z2` tool used in conjunction with it.

## Running a Node

To start a node you need to pass a private key as a command line parameter.
This will be interpreted as both a BLS private key and a libp2p secp256k1 private key (of course the corresponding public keys will be different).

You will need to start at least 4 nodes before the network will begin to make progress.

### Example invocations for a network with 4 nodes

Note: You must include the public key and peer ID of one of the nodes in the config with the argument `-c`

```
cargo run --bin zilliqa -- 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c ./infra/config.toml
cargo run --bin zilliqa -- 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e  -c ./infra/config_rpc_disabled.toml
cargo run --bin zilliqa -- 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364 -c ./infra/config_rpc_disabled.toml
cargo run --bin zilliqa -- db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a -c ./infra/config_rpc_disabled.toml
```

You may also want to set `RUST_LOG=zilliqa=trace` to see the most detailed level of logs.

### Running with z2

The `z2` program in this repository will run a small local Zilliqa
network for you, for debugging. This will include `otterscan`,
`spout`, a mitmweb API proxy and the documentation. Do:

```bash
./scripts/z2 depends print
./scripts/z2 depends update
```

To print or update dependencies, and

```bash
./scripts/z2 run /tmp/c
```

To run the network, where `/tmp/c` is a directory in which `z2` will place configuration files. You can run:

```bash
./scripts/z2
```

for help.

### Bootstrap with docker-compose

Automated bootstrap of a 4 nodes Zilliqa 2.0 aka zq2 network.

Run:

```bash
docker-compose up
```

## Node configuration

Nodes are configured by TOML files.
Pass the path to configuration files on the command line with `-c` or `--config-file`.
If multiple configuration files are provided, they will be merged together.
If a configuration key occurs in more than one configuration file, the process will exit with an error.

## Testing

The tests can be run with `cargo test`.
Most tests create an in-memory network of nodes, with the libp2p networking layer stubbed out and send API requests to the network.

Some tests involve compiling Solidity code.
`svm-rs` will automatically download and use a suitable version for your platform when you run these tests.

To install `svm-rs` run:

```
cargo install svm-rs
```

Then you can install a suitable Solc version by executing:

```
svm install <solc version>
```

## Logging

You can get log output globally via

```unset
RUST_LOG=zilliqa=[warn|info|debug|trace]
```

Or via individual modules using eg.

```unset
RUST_LOG=debug,sled=info,zilliqa::scilla=trace
```

## `rustfmt`

We use a couple of nightly-only rustfmt features. The easiest way to get these is:

```sh
rustup toolchain install nightly
cargo +nightly fmt
```

## Supported APIs

The supported API table is now auto-generated. You can get one by running:

```sh
./scripts/zq2 doc-gen /tmp/mydir
```

and then looking in `/tmp/mydir/supported_apis.md`

Of the currently undocumented APIs, the following are partially implemented:

  * `eth_getBlockByHash` (issue #79)
  * `eth_getBlockByNumber` (issue #79)
  * `eth_syncing`
  * `net_peerCount`

## Denial of Service

Refer to `docs/denialofservice.md` for a collection of guides to help mitigate the issue.