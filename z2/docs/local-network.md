# z2 local network

The `z2` tool allows you to run a simple Zilliqa 2 network locally for debugging.

## Setup

Install dependencies

```bash
    sudo apt install mitmproxy npm
```

Create a new directory and pull zq2

```bash
    mkdir /some/dir
    cd /some/dir
    git clone git@github.com:zilliqa/zq2
```

Use the `depends` tool to pull all dependencies:

```bash
    cd zq2
    ./scripts/z2 depends update
```

This will pull dependencies to the parent directory. You will need to build scilla manually, see instructions in it's repo.

You can then invoke a local ZQ2 network with:

```bash
    cargo build
    ./scripts/z2 run /tmp/some_dir
```

For help run:

```bash
    ./scripts/z2
```

It will:

 * Generate some configuration in `/tmp/some_dir`
 * Start up some otel containers to do telemetry
 * Start a 4-node Zilliqa 2 network
 * Start otterscan
 * Start a mitmweb proxy so you can debug RPC calls
 * Start a faucet so you can get some ZIL

otterscan runs directly to node 0 (without going through the proxy)
because developer tools in chrome gives a decent RPC debugger and this
allows you to see "just" the traffic from your app and from the
faucet without the otterscan polls getting in the way.

`z2` will set up ports as offsets from a port base, which is by default 4000:

```
🦏  JSON-RPC ports are at 4201+<node_index>
🦏  Spout is at http://localhost:6001/
🦏  mitmproxy port at http://localhost:6002/
🦏  Otterscan: http://localhost:6003/
```

In the future, we will also have the ability to manage persistence: watch this space.

## Genesis accounts

`z2` configures a genesis account with:

```
export PRIVATE_KEY=0xdb11cfa086b92497c8ed5a4cc6edb3a5bfe3a640c43ffb9fc6aa0873c56f2ee3
export ZIL_ADDRESS=0x7bb3b0e8a59f3f61d9bff038f4aeb42cae2ecce8
export ETH_ADDRESS=0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415
```
