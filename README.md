# Zilliqa 2.0 - The next evolution of Zilliqa

Further documentation can be found in the `docs/` directory, for Zilliqa 2 itself, and in `z2/docs` for the `z2` tool used in conjunction with it.

## Running a Node

To start a node you need to pass a private key as a command line parameter.
This will be interpreted as both a BLS private key and a libp2p secp256k1 private key (of course the corresponding public keys will be different).

You will need to start at least 4 nodes before the network will begin to make progress.

### Example invocations for a network with 4 nodes

Note: You must include the public key and peer ID of one of the nodes in the config with the argument `-c`

```
cargo run --bin zilliqa -- 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c ./infra/config_docker.toml
cargo run --bin zilliqa -- 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e  -c ./infra/config_rpc_disabled.toml
cargo run --bin zilliqa -- 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364 -c ./infra/config_rpc_disabled.toml
cargo run --bin zilliqa -- db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a -c ./infra/config_rpc_disabled.toml
```

You may also want to set `RUST_LOG=zilliqa=trace` to see the most detailed level of logs.

### Running with z2

The `z2` program in this repository will run a small local Zilliqa network for you, for debugging. This will include `otterscan`, `spout`, a mitmweb API proxy and the documentation.

`z2` utility tool usage instructions can be found [here](./z2/docs/README.md). Instructions for running a local network using z2 are [here](./z2/docs/local-network.md).


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

By default, a node will not expose the JSON-RPC API.
To enable APIs, you must set `api_servers` under the [[nodes]] object in the configuration file.
Each item must be an object with keys `port` and `enabled_apis`.
Each item in `enabled_apis` must either be:

* A string such as `"eth"`, which enables all API methods under the `eth_` namespace.
* An object of the form `{ namespace = "eth", apis = ["blockNumber"] }`, which enables specific API methods.

Zilliqa APIs which don't have a namespace are implicitly grouped under the `zilliqa` namespace.

See `config-example.toml` for a configuration example.

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

### Tests with JMeter

JMeter for performance and load tests is integrated in the Github Action pipelines in `.github/workflows/test_performance.yaml` and can be manually executed from the Github console with custom and default parameters. The test executions are restricted to users of the Zilliqa organization.

## Running benchmarks

Benchmarks can be run with `cargo bench --package zilliqa --bench it`.
To run a specific benchmark, append ` -- <benchmark-name>` to the command.

It can also be helpful to generate flamegraphs from benchmarks to see where time is being spent.
Append `--profile-time <time in seconds>` to the command to continue running the benchmark for the specified period of time, rather than stopping when enough samples have been gathered.
You should select `profile-time` to be long enough to gather a representative set of samples.
150 seconds has been a reasonable value in testing.
After running this, a flamegraph should exist in `target/criterion/<benchmark-name>/<benchmark-name>/profile/flamegraph.svg`.
Make sure to open the `.svg` in a web browser - the embedded JS provides some useful features for exploring the graph (such as being able to click on functions and CTRL+F).

## Logging

You can get log output globally via

```unset
RUST_LOG=zilliqa=[warn|info|debug|trace]
```

Or via individual modules using eg.

```unset
RUST_LOG=debug,sled=info,zilliqa::scilla=trace
```

## Observability

### OpenTelemetry

OpenTelemetry metrics from the Zilliqa nodes container are available when the OTLP collector endpoint is defined in the configuration.

```yaml
otlp_collector_endpoint = "http://otel-collector:4317"
```

There is a docker-compose project that includes the OpenTelemetry configuration and tech stack that can be run in local environment for testing purposes:

```bash
docker-compose -f infra/opentelemetry/compose.yaml up -d
```

After the services are running, a sample dashboard could be obtained from the (Grafana)[http://localhost:9010] local service.

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
  * `net_peerCount`

## zurl - IAP Tunnel Curl Wrapper

`zurl` is a curl wrapper that automatically manages Google Cloud IAP tunnels for accessing private instances.

### Usage

Login to GCP and set the environment variables and paths.

```sh
source scripts/setenv
```

Use exactly like curl, but with your private instance hostname:

```bash
zurl [curl-options] "instance-name:port[/path]"
```

To see more information, you can use the --debug parameter:

```bash
zurl --debug [curl-options] "instance-name:port[/path]"
```

### Project Auto-Detection

Automatically selects the correct GCP project based on instance name:
- `zq2-devnet-*` → `prj-d-zq2-devnet-c83bkpsd`
- `zq2-testnet-*` → `prj-d-zq2-testnet-g13pnaa8`
- `zq2-mainnet-*` → `prj-p-zq2-mainnet-sn5n8wfl`
- Default: `prj-p-zq2-mainnet-sn5n8wfl`

### Example

```bash
zurl -d '{
    "id": "1",
    "jsonrpc": "2.0", 
    "method": "eth_blockNumber"
}' -H "Content-Type: application/json" -X POST "zq2-devnet-api-ase1-2:4201"
```

Output:
```
{"jsonrpc":"2.0","id":"1","result":"0x17a2b"}
```