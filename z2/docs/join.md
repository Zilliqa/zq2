# z2 join

`z2 join` creates the validator node startup script and configuration file.

```bash
Join a ZQ2 network

Usage: z2 join --chain <CHAIN_NAME>

Options:
      --chain <CHAIN_NAME>  Specify the ZQ2 chain you want join [possible values: zq2-prototestnet]
  -h, --help                Print help
```

## Prerequisites

Before proceeding with the setup, please ensure that you meet the following requirements:

- **Public IPv4 Address:** A public IPv4 address is mandatory for your validator node to join the Zilliqa network. This IP address will be automatically used during the node configuration process.

### Why a Public IPv4 Address is Required

Zilliqa nodes rely on a public IPv4 address to communicate with the rest of the network. During the setup process, this IP address is automatically detected and used to generate the node configuration file. Without a public IPv4 address, the node will not be able to properly join or participate in the network.

## Create a startup script and configuration file to join the prototestnet

```bash

z2 join --chain zq2-prototestnet
✌️ Generating the validator startup scripts and configuration
📋 Chain specification: zq2-prototestnet
👤 Role: External Validator
💾 Validator config: /path/to/zq2/zq2-prototestnet.toml
💾 Startup script: /path/to/zq2/start_validator.sh
```

> **Important note:** to generate the validator node configuration file, `z2 join` will automatically detect your public IPv4 address and add it to the configuration. Please ensure that your public IPv4 address is static or, if dynamic as a changing IP address can disrupt your node's participation in the network.

## Run the validator

To run the validator you need to create a PRIVATE KEY for you node.
Any 32 byte Hex string is valid. Ensure you save it after on a safe place, in case you need
to restart your node.

Copy the above generated Validator config and startup script to an Ubuntu 20.04LTS with
Docker version 26.1+.

>Info: the start_validator.sh and the zq2-prototestnet.toml MUST be on the same directory.

On the Ubuntu 20.04LTS run:

### (Optional) Generate the node private key

`export PRIVATE_KEY=$(openssl rand -hex 32)`

### Use an existing key

`export PRIVATE_KEY=<put your key here>`


```bash
chmod +x /path/to/zq2/start_validator.sh

/path/to/zq2/start_validator.sh $PRIVATE_KEY
```

# How-to use a custom docker image

If you want to use a custom docker image you need to edit the generated `/path/to/zq2/start_validator.sh` changing the following variables:

```bash
ZQ_VERSION="e5f75649"
ZQ2_IMAGE="asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zq2:${ZQ_VERSION}"
```

# How-to customize the node configuration file

If you need to customize your node configuration you need to edit the generated `<chain-name>.toml` file.