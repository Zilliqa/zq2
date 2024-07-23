# z2 join

`z2 join` creates the validator node startup script and configuration file.

```bash
Join a ZQ2 network

Usage: z2 join --chain <CHAIN_NAME>

Options:
      --chain <CHAIN_NAME>  Specify the ZQ2 chain you want join [possible values: zq2-prototestnet]
  -h, --help                Print help
```

## Create a startup script and configuration file to join the prototestnet

```bash

z2 join --chain zq2-prototestnet
✌️ Generating the validator startup scripts and configuration
📋 Chain specification: zq2-prototestnet
👤 Role: External Validator
💾 Validator config: /path/to/zq2/zq2-prototestnet.toml
💾 Startup script: /path/to/zq2/start_validator.sh
```

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
ZQ2_IMAGE="zilliqa/zq2:${ZQ_VERSION}"
```

# How-to customize the node configuration file

If you need to customize your node configuration you need to edit the generated `<chain-name>.toml` file.