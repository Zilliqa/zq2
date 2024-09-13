# z2 deployer

`z2 deployer` allows you to create a deployment configuration file for a `zq2` network, and perform a seamless and automated upgraded.

```bash
z2 deployer --help
```

```bash
Group of subcommands to deploy and configure a Zilliqa 2 network

Usage: z2 deployer [OPTIONS] <COMMAND>

Commands:
  new                   Generate the deployer config file
  install               Install the network defined in the deployer config file
  upgrade               Update the network defined in the deployer config file
  get-deposit-commands  Generate in output the commands to deposit stake amount to all the validators
  deposit               Deposit the stake amounts to all the validators
  help                  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

## To use it:

- Log in to Zilliqa GCP landing zone: `gcloud auth login --update-adc`

## Create a new deployer upgrader configuration file

The generated configuration file will be named: `zq2`-`<network-name>`.yaml
```bash
z2 deployer new --help
```

```bash
Generate the deployer config file

Usage: z2 deployer new [OPTIONS]

Options:
      --network-name <NETWORK_NAME>
          ZQ2 network name

      --eth-chain-id <ETH_CHAIN_ID>
          ZQ2 EVM chain ID

      --project-id <PROJECT_ID>
          GCP project-id where the network is running

      --roles <ROLES>
          Virtual Machine roles

          Possible values:
          - bootstrap:  Virtual machine bootstrap
          - validator:  Virtual machine validator
          - api:        Virtual machine api
          - apps:       Virtual machine apps
          - checkpoint: Virtual machine checkpoint
          - sentry:     Virtual machine sentry

  -v, --verbose...
          Increase logging verbosity

  -q, --quiet...
          Decrease logging verbosity

  -h, --help
          Print help (see a summary with '-h')
```

### Usage example

#### Scenario 1

Generate the deployer configuration file to upgrade the validator nodes of the `zq2-prototestnet` with chain ID `33333` and running on a GCP project named `gcp-tests`.

```
Network name: `zq2-prototestnet`
Project Id: `gcp-tests`
Roles: validators
```

```bash
z2 deployer new --network-name zq2-prototestnet --eth-chain-id 33333 --project-id gcp-tests --roles validator
```

Output: `zq2-prototestnet.yaml`

```yaml
name: zq2-prototestnet
eth_chain_id: 33333
project_id: gcp-tests
roles:
- validator
versions:
  zq2: 5522b056
  ```

#### Scenario 2

Generate the deployer configuration file for upgrade the app node of the `zq2-prototestnet` with chain ID `33333` and running on a GCP project named `gcp-tests`.

```yaml
Network name: zq2-prototestnet
Eth Chain ID: 33333
Project ID: gcp-tests
Roles: apps
```

```bash
z2 deployer new --network-name zq2-prototestnet --eth-chain-id 33333 --project-id gcp-tests --roles apps
```

Output: `zq2-prototestnet.yaml`

```yaml
name: zq2-prototestnet
eth_chain_id: 33333
project_id: gcp-tests
roles:
- apps
versions:
  spout: v1.3.72
  otterscan: latest
```

#### Scenario 3

Generate the deployer configuration file for upgrade both validators and app nodes of the `zq2-prototestnet` with chain ID `33333` and running on a GCP project named `gcp-tests`.

```yaml
Network name: zq2-prototestnet
Eth Chain ID: 33333
Project ID: gcp-tests
Roles: apps,validator
```

```bash
z2 deployer new --network-name zq2-prototestnet --eth-chain-id 33333 --project-id gcp-tests --roles apps,validator
```

Output: `zq2-prototestnet.yaml`

```yaml
name: zq2-prototestnet
eth_chain_id: 33333
project_id: gcp-tests
roles:
- validator
- apps
versions:
  zq2: fbee9ec5
  spout: v1.3.72
  otterscan: latest
```

By default, the `z2 deployer new` will generate a configuration file with the current Github release.
If there are no release available the value are defaulted to the 8 characters of the latest commit SHA in the `main` branch.

>Note: Make sure to provide the correct values when the defaults are not suitable.


## Upgrade the network

```bash
z2 deployer upgrade --help
```

```bash
Update the network defined in the deployer config file

Usage: z2 deployer upgrade [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

Upgrade to a new version the `zq2-prototestnet` nodes

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer upgrade zq2-prototestnet.yaml
```

## Install the network

```bash
z2 deployer install --help
```

```bash
Install the network defined in the deployer config file

Usage: z2 deployer install [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

> Same as `upgrade` subcommand, but skipping the check if the nodes are receiving new blocks

## Retrieve the commands to deposit stake amount to all the validators

```bash
z2 deployer get-deposit-commands --help
```

```bash
Generate in output the commands to deposit stake amount to all the validators

Usage: z2 deployer get-deposit-commands [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

Retrieve the commands to deposit the stake amounts to the `zq2-prototestnet` validators

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer get-deposit-commands zq2-prototestnet.yaml
```

## Deposit the stake amounts to all the validators

```bash
z2 deployer deposit --help
```

```bash
Deposit the stake amounts to all the validators

Usage: z2 deployer deposit [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

Deposit the stake amounts to the `zq2-prototestnet` validators

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer deposit zq2-prototestnet.yaml
```

## Run RPC calls over all the nodes

```bash
z2 deployer rpc --help
```

```bash
Run RPC calls over the internal network nodes

Usage: z2 deployer rpc [OPTIONS] --method <METHOD> <CONFIG_FILE>

Arguments:
  <CONFIG_FILE>  The network deployer config file

Options:
  -m, --method <METHOD>  Method to run
  -p, --params <PARAMS>  List of parameters for the method. ie "["string_value", true]"
  -v, --verbose...       Increase logging verbosity
  -q, --quiet...         Decrease logging verbosity
  -h, --help             Print help
```

### Usage example

#### Scenario

Get the current block height in the `zq2-prototestnet` nodes

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer rpc -m eth_blockNumber zq2-prototestnet.yaml
```
