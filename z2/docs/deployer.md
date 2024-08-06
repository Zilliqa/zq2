# z2 deployer

`z2 deployer` allows you to create a deployment configuration file for a `zq2` network, and perform a seamless and automated upgraded.

```bash
z2 deployer --help
Deploy Zilliqa 2

Usage: z2 deployer <COMMAND>

Commands:
  new      Generate the deployer config file
  upgrade  Perfom the network upgrade
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
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

      --project-id <PROJECT_ID>
          GCP project-id where the network is running

      --roles <ROLES>
          Virtual Machine roles

          Possible values:
          - bootstrap:  Virtual machine bootstrap
          - api:        Virtual machine api
          - apps:       Virtual machine apps
          - validator:  Virtual machine validator
          - checkpoint: Virtual machine checkpoint
          - sentry:     Virtual machine sentry

  -h, --help
          Print help (see a summary with '-h')
```

### Usage example

#### Scenario 1

Generate the deployer configuration file for upgrade the validator nodes of the `zq2-prototestnet` running on a GCP project named `gcp-tests`.

```
Network name: `zq2-prototestnet`
Project Id: `gcp-tests`
Roles: validators
```

```bash
z2 deployer new --network-name zq2-prototestnet --project-id gcp-tests --roles validator
```

Output: `zq2-prototestnet.yaml`

```yaml
name: zq2-prototestnet
project_id: gcp-tests
roles:
- validator
versions:
  zq2: 5522b056
  ```

#### Scenario 2

Generate the deployer configuration file for upgrade the app node of the `zq2-prototestnet` running on a GCP project named `gcp-tests`.

```
Network name: `zq2-prototestnet`
Project Id: `gcp-tests`
Roles: apps
```

```bash
z2 deployer new --network-name zq2-prototestnet --project-id gcp-tests --roles apps
```

Output: `zq2-prototestnet.yaml`

```yaml
name: zq2-prototestnet
project_id: gcp-tests
roles:
- apps
versions:
  spout: v1.3.72
  otterscan: latest
```

#### Scenario 3

Generate the deployer configuration file for upgrade both validators and app nodes of the `zq2-prototestnet` running on a GCP project named `gcp-tests`.

```
Network name: `zq2-prototestnet`
Project Id: `gcp-tests`
Roles: apps
```

```bash
z2 deployer new --network-name zq2-prototestnet --project-id gcp-tests --roles validator,apps
```

Output: `zq2-prototestnet.yaml`

```yaml
name: zq2-prototestnet
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
Perfom the network upgrade
Usage: z2 deployer upgrade [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]  

Options:
  -h, --help  Print help
```

### Usage example

#### Scenario

Network name: `zq2-prototestnet`
Configuration file: `zq2-prototestnet.yaml`

```bash
z2 deployer upgrade zq2-prototestnet.yaml
```

## Retrieve the `z2 deposit` commands for the validator nodes

```bash
z2 deployer get-deposit-commands --help
```

```bash
Provide the deposit commands for the validator nodes

Usage: z2 deployer get-deposit-commands [CONFIG_FILE]

Arguments:
  [CONFIG_FILE]

Options:
  -h, --help  Print help
```

### Usage example

#### Scenario

Network name: `zq2-prototestnet`
Configuration file: `zq2-prototestnet.yaml`

```bash
z2 deployer get-deposit-commands zq2-prototestnet.yaml
```
