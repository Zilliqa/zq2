# z2 deployer

`z2 deployer` allows you to create a deployment configuration file for a `zq2` network, and perform a seamless and automated upgraded.

```bash
z2 deployer --help
```

```bash
Group of subcommands to deploy and configure a Zilliqa 2 network

Usage: z2 deployer [OPTIONS] <COMMAND>

Commands:
  install                Install the network defined in the deployer config file
  upgrade                Update the network defined in the deployer config file
  get-config-file        Generate in output the validator config file to join the network
  get-deposit-commands   Generate in output the commands to deposit stake amount to all the validators
  deposit                Deposit stake amounts to the internal validators
  deposit-top-up         Top up stake to the internal validators
  unstake                Unstake funds of the internal validators
  withdraw               Withdraw unstaked funds to the internal validators
  stakers                Show network stake information
  rpc                    Run RPC calls over the internal network nodes
  ssh                    Run command over SSH in the internal network nodes
  backup                 Backup a node data dir in the persistence bucket
  restore                Restore a node data dir from a backup in the persistence bucket
  reset                  Reset a network stopping all the nodes and cleaning the /data folder
  restart                Restart a network stopping all the nodes and starting the service again
  monitor                Monitor the network nodes specified metrics
  help                   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

## To use it:

- Log in to Zilliqa GCP landing zone: `gcloud auth login --update-adc`

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
      --select                       Enable nodes selection
      --max-parallel <MAX_PARALLEL>  Define the number of nodes to process in parallel. Default: 1
  -v, --verbose...                   Increase logging verbosity
  -q, --quiet...                     Decrease logging verbosity
  -h, --help                         Print help
```

### Usage example

#### Scenario - Upgrade all the nodes

Upgrade to a new version the `zq2-prototestnet` nodes

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer upgrade zq2-prototestnet.yaml
```

#### Scenario - Upgrade only selected nodes

Upgrade to a new version the `zq2-prototestnet` validators

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer upgrade --select zq2-prototestnet.yaml
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
      --select
          Enable nodes selection
      --max-parallel <MAX_PARALLEL>
          Define the number of nodes to process in parallel. Default: 50
      --persistence-url <PERSISTENCE_URL>
          gsutil URI of the persistence file. Ie. gs://my-bucket/my-folder
      --checkpoint-url <CHECKPOINT_URL>
          gsutil URI of the checkpoint file. Ie. gs://my-bucket/my-file. By enabling this option the install will be performed only on the validator nodes
  -v, --verbose...
          Increase logging verbosity
  -q, --quiet...
          Decrease logging verbosity
  -h, --help
          Print help
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
      --select      Enable nodes selection
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
Deposit stake amounts to the internal validators

Usage: z2 deployer deposit [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
      --select      Enable nodes selection
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

## Top up stake deposit to the internal validators

```bash
z2 deployer deposit-top-up --help
```

```bash
Top up stake to the internal validators

Usage: z2 deployer deposit-top-up [OPTIONS] --amount <AMOUNT> [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
      --select           Enable nodes selection
      --amount <AMOUNT>  Specify the amount in millions
  -v, --verbose...       Increase logging verbosity
  -q, --quiet...         Decrease logging verbosity
  -h, --help             Print help
```

### Usage example

#### Scenario

Top up the stake deposit amounts to the `zq2-prototestnet` validators

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer deposit-top-up --amount 10 zq2-prototestnet.yaml
```

## Unstake funds of the internal validators

```bash
z2 deployer unstake --help
```

```bash
Unstake funds of the internal validators

Usage: z2 deployer unstake [OPTIONS] --amount <AMOUNT> [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
      --select           Enable nodes selection
      --amount <AMOUNT>  Specify the amount in millions
  -v, --verbose...       Increase logging verbosity
  -q, --quiet...         Decrease logging verbosity
  -h, --help             Print help
```

### Usage example

#### Scenario

Unstake deposit amounts to the `zq2-prototestnet` validators

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer unstake --amount 10 zq2-prototestnet.yaml
```

## Withdraw unstaked funds to the internal validators

```bash
z2 deployer withdraw --help
```

```bash
Withdraw unstaked funds to the internal validators

Usage: z2 deployer withdraw [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
      --select      Enable nodes selection
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

Withdraw unstaked funds to the `zq2-prototestnet` validators

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer withdraw zq2-prototestnet.yaml
```

## Show network stake information

```bash
z2 deployer stakers --help
```

```bash
Show network stake information

Usage: z2 deployer stakers [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

Show the stake and future stake amount of the `zq2-prototestnet` network

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer stakers zq2-prototestnet.yaml
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
      --timeout <TIMEOUT>  Specifies the maximum time (in seconds) allowed for the entire request. Default: 30
  -m, --method <METHOD>    Method to run
      --params <PARAMS>    List of parameters for the method. ie "[\"string_value\",true]"
      --select             Enable nodes selection
  -p, --port <PORT>        The port where to run the rpc call on [possible values: default, admin]
  -v, --verbose...         Increase logging verbosity
  -q, --quiet...           Decrease logging verbosity
  -h, --help               Print help
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

## Run SSH commands over all the nodes

```bash
z2 deployer ssh --help
```

```bash
Run command over SSH in the internal network nodes

Usage: z2 deployer ssh [OPTIONS] <CONFIG_FILE> [COMMAND]...

Arguments:
  <CONFIG_FILE>  The network deployer config file
  [COMMAND]...   Method to run

Options:
      --select      Enable nodes selection
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

Start the zilliqa service in the `zq2-prototestnet` nodes

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer ssh zq2-prototestnet.yaml -- "sudo systemctl start zilliqa.service"
```

## Generate in output the config file to join the network

```bash
z2 deployer get-config-file --help
```

```bash
Generate in output the validator config file to join the network

Usage: z2 deployer get-config-file [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]
          The network deployer config file

Options:
      --role <ROLE>
          Node role. Default: validator

          Possible values:
          - bootstrap:   Virtual machine bootstrap
          - validator:   Virtual machine validator
          - api:         Virtual machine api
          - private-api: Virtual machine private api
          - apps:        Virtual machine apps
          - checkpoint:  Virtual machine checkpoint
          - persistence: Virtual machine persistence
          - sentry:      Virtual machine sentry

      --out <OUT>
          File to output to

  -v, --verbose...
          Increase logging verbosity

  -q, --quiet...
          Decrease logging verbosity

  -h, --help
          Print help (see a summary with '-h')
```

### Usage example

#### Scenario

Get the config file for a node role `api` in the `zq2-prototestnet` nodes

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer get-config-file --role api zq2-prototestnet.yaml
```

#### Scenario

Save the config file for a node role `validator` in the `zq2-prototestnet` nodes

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer get-config-file --role validator zq2-prototestnet.yaml --out ./z2/resources/chain-specs/zq2-prototestnet.toml
```

## Backup a node data dir

```bash
z2 deployer backup --help
```

```bash
Backup a node data dir in the persistence bucket

Usage: z2 deployer backup [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
  -n, --name <NAME>  The name of the backup folder. If zip is specified, it represents the name of the zip file
      --zip          If specified, create a zip file containing the backup
  -v, --verbose...   Increase logging verbosity
  -q, --quiet...     Decrease logging verbosity
  -h, --help         Print help
```

### Usage example

#### Scenario

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer backup --file /tmp/data.zip zq2-prototestnet.yaml
```

## Restore a node's data dir from a backup

```bash
z2 deployer restore --help
```

```bash
Restore a node data dir from a backup in the persistence bucket

Usage: z2 deployer restore [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
  -n, --name <NAME>                  The name of the backup folder. If zip is specified, it represents the name of the zip file
      --zip                          If specified, restore the persistence from a zip file
      --max-parallel <MAX_PARALLEL>  Define the number of nodes to process in parallel. Default: 50
  -v, --verbose...                   Increase logging verbosity
  -q, --quiet...                     Decrease logging verbosity
  -h, --help                         Print help
```

### Usage example

#### Scenario

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer restore --file /tmp/data.zip zq2-prototestnet.yaml
```

## Reset network nodes

```bash
z2 deployer reset --help
```

```bash
Reset a network stopping all the nodes and cleaning the /data folder

Usage: z2 deployer reset [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
      --select      Enable nodes selection
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer reset zq2-prototestnet.yaml
```

## Restart network nodes

```bash
z2 deployer restart --help
```

```bash
Restart a network stopping all the nodes and starting the service again

Usage: z2 deployer restart [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
      --select      Enable nodes selection
  -v, --verbose...  Increase logging verbosity
  -q, --quiet...    Decrease logging verbosity
  -h, --help        Print help
```

### Usage example

#### Scenario

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer restart zq2-prototestnet.yaml
```

## Monitor the network nodes specified metrics

```bash
z2 deployer monitor --help
```

```bash
Monitor the network nodes specified metrics

Usage: z2 deployer monitor [OPTIONS] [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  The network deployer config file

Options:
      --metric <METRIC>  The metric to display. Default: block-number [possible values: block-number, consensus-info]
      --select           Enable nodes selection
      --follow           After showing the metrics, watch for changes
  -v, --verbose...       Increase logging verbosity
  -q, --quiet...         Decrease logging verbosity
  -h, --help             Print help
```

### Usage example

#### Monitor the nodes blocknumber

```yaml
Network name: zq2-prototestnet
Configuration file: zq2-prototestnet.yaml
```

```bash
z2 deployer monitor --metric block-number --follow zq2-prototestnet.yaml
```
