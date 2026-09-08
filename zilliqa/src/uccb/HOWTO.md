# How To Run UCCB Locally

It is possible to run UCCB on a local node, for local testing.
While the instructions here work on a single node, running it on the local docker network will work as well.

## Run a Node

You can simply run a single node with the pre-configured settings.

```
$ RUST_LOG=info cargo run --bin zilliqa -- -c bundler_tests/config-bundler-spec-tests.toml | grep "uccb"
```

## Deploy Entrypoint

Get the Account Abstraction code from here:
https://github.com/eth-infinitism/account-abstraction

Deploy the original Entrypoint v0.9 to the node.
Although it is possible to run either v0.8/v0.9, the local node has been pre-configured to work with v0.9 only.

```
$ git checkout v0.9.0
$ yarn install
$ yarn deploy --network proxy --reset
```

## Deploy UCCB Contracts

Deploy the UCCB contracts to the node.
These contracts are written to use the latest Entrypoint provided by OpenZeppelin, which is Entrypoint v0.9 as of OZ version 5.6.x.

```
$ bash bundler_tests/deploy_uccb.sh
```

This script does several things:
- Registers ORIGINATOR contracts/accounts that are allowed to make the `sendMessage()` call that starts the flow.
- Registers RECEIVER contracts/accounts that are allowed to are called from `receiveMessage()` that terminates the flow.
- Perform the deposit and staking that are needed for the SENDER and PAYMASTER contracts.
- Registers the SENDER contract on the PAYMASTER that it will sponsor gas fees for (simple sponsored sender flow).
- Registers the SENDER contract on the GATEWAY that it will interact with.
- Registers the set of SIGNERS on the SENDER that are used to validate signatures.

## Bundler

Get the Rundler from here:
https://github.com/shawn-zil/rundler/tree/fix/op-062-core-precompiles

Build it and then run it under the following environment.

Environment settings
```
NETWORK=dev
CHAIN_ID=1337
NODE_HTTP=http://localhost:8545
RUST_LOG=info
RPC_API=eth,debug
RPC_PORT=3545
METRICS_HOST=127.0.0.1
MIN_UNSTAKE_DELAY=2
PRIORITY_FEE_MODE_KIND=base_fee_percent
PRIORITY_FEE_MODE_VALUE=0
SIGNER_PRIVATE_KEYS="0x0000000000000000000000000000000000000000000000000000000000000002,0x0000000000000000000000000000000000000000000000000000000000000003,0x0000000000000000000000000000000000000000000000000000000000000004"
MAX_VERIFICATION_GAS=10000000
TRACER_TIMEOUT=25s
PROVIDER_CLIENT_TIMEOUT_SECONDS=30
ENABLED_ENTRY_POINTS="v0.9"
```

## Execute

Call a remote contract.
The following command invokes the `Gateway.sendMessage()` to call the `entryPoint()` function on the deployed `Simple7702Account` installed with the Entrypoint.

This triggers a loop-back:
- the message originates on the local node;
- the userop is submitted to the bundler;
- the bundler simulates and submits the bundle to the entrypoint;
- the recipient is called via the entrypoint.

```
$ cast send $GW_PROXY "sendMessage(bytes,bytes,bytes[])" 0001000002053914a46cc63eBF4Bd77888AA327837d20b23A63a56B5 0xb0d691fe "[]" --private-key $PRIVATE_KEY
```
