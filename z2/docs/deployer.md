# z2 deployer User Guide & Manual

## 1. Introduction

`z2 deployer` is the command-line tool for deploying, managing, and maintaining Zilliqa 2 (ZQ2) networks. It automates network installation, upgrades, staking operations, configuration management, and more, making it the central tool for ZQ2 network operators and advanced users.

---

## 2. Prerequisites & Setup

- **GCP Access:** Ensure you have access to the Zilliqa GCP landing zone and the required permissions for your target network.
- **Authentication:**
  - Log in to GCP: `gcloud auth login --update-adc`
  - Set up any required environment variables (see your team's onboarding guide).
- **Install z2 CLI:**
  - Build from source or download the latest release as per your platform.
- **Dependencies:**
  - Docker (for node management)
  - gsutil (for interacting with Google Cloud Storage)

---

## 3. Deployer Configuration File

### 3.1 Structure

The deployer configuration file defines the network topology, node roles, versions, and other deployment parameters. It must be written in **YAML** format.

**Key fields:**
- `name`: Name of the network (e.g., `zq2-testnet`)
- `eth_chain_id`: Ethereum-compatible chain ID
- `roles`: List of node roles (e.g., `validator`, `api`, `bootstrap`)
- `versions`: Mapping of component names to versions/tags

### 3.2 Example

```yaml
name: zq2-testnet
eth_chain_id: 33103
roles:
  - bootstrap
  - validator
  - api
  - apps
  - opsnode
  - private-api
versions:
  zq2: v0.10.0
```

> **Note:** This is a minimal example. Your actual config may include additional fields for advanced setups. Refer to your team's templates or onboarding documentation for full examples.

### 3.3 How to Create and Validate
- Start from a template provided by your team or the Zilliqa repo.
- Edit with your preferred YAML editor.
- Validate with `yamllint` or similar tools to avoid syntax errors.
- Store securely and version-control your config files.

---

## 4. Subcommands Reference

Each subcommand manages a specific aspect of the network. All commands accept `-v/--verbose` and `-q/--quiet` for logging control.

### 4.1 install
**Purpose:** Install the network as defined in the deployer config file.

**Usage:**
```bash
z2 deployer install [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes
- `--max-parallel <N>` — number of nodes to process in parallel (default: 50)
- `--persistence-url <URL>` — gsutil URI for persistence file
- `--checkpoint-url <URL>` — gsutil URI for checkpoint file (validators only)

**Example:**
```bash
z2 deployer install --max-parallel 10 --persistence-url gs://my-bucket/persistence.tar zq2-testnet.yaml
```

### 4.2 upgrade
**Purpose:** Upgrade the network to new versions as defined in the config file.

**Usage:**
```bash
z2 deployer upgrade [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes
- `--max-parallel <N>` — number of nodes to process in parallel (default: 1)

**Example:**
```bash
z2 deployer upgrade zq2-testnet.yaml
```

### 4.3 get-config-file
**Purpose:** Generate a node configuration file for joining the network.

**Usage:**
```bash
z2 deployer get-config-file [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--role <ROLE>` — node role (default: validator)
- `--out <PATH>` — output file path

**Example:**
```bash
z2 deployer get-config-file --role api --out ./z2/resources/chain-specs/zq2-testnet-api.toml zq2-testnet.yaml
```

### 4.4 get-deposit-commands
**Purpose:** Output the commands needed to deposit stake for all validators.

**Usage:**
```bash
z2 deployer get-deposit-commands [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes

**Example:**
```bash
z2 deployer get-deposit-commands zq2-testnet.yaml
```

### 4.5 deposit
**Purpose:** Deposit stake for all internal validators.

**Usage:**
```bash
z2 deployer deposit [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes

**Example:**
```bash
z2 deployer deposit zq2-testnet.yaml
```

### 4.6 deposit-top-up
**Purpose:** Top up stake for validators.

**Usage:**
```bash
z2 deployer deposit-top-up --amount <AMOUNT> [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes
- `--amount <AMOUNT>` — amount in ZILs (required)

**Example:**
```bash
z2 deployer deposit-top-up --amount 10 zq2-testnet.yaml
```

### 4.7 unstake
**Purpose:** Unstake funds for validators.

**Usage:**
```bash
z2 deployer unstake --amount <AMOUNT> [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes
- `--amount <AMOUNT>` — amount in ZILs (required)

**Example:**
```bash
z2 deployer unstake --amount 10 zq2-testnet.yaml
```

### 4.8 withdraw
**Purpose:** Withdraw unstaked funds for validators.

**Usage:**
```bash
z2 deployer withdraw [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes

**Example:**
```bash
z2 deployer withdraw zq2-testnet.yaml
```

### 4.9 stakers
**Purpose:** Show network stake and future stake information.

**Usage:**
```bash
z2 deployer stakers <CONFIG_FILE>
```
**Example:**
```bash
z2 deployer stakers zq2-testnet.yaml
```

### 4.10 rpc
**Purpose:** Run RPC calls on internal network nodes.

**Usage:**
```bash
z2 deployer rpc [OPTIONS] --method <METHOD> <CONFIG_FILE>
```
**Options:**
- `--timeout <SECONDS>` — request timeout (default: 30)
- `-m, --method <METHOD>` — RPC method to call (required)
- `--params <PARAMS>` — parameters as JSON string
- `--select` — interactively select nodes
- `-p, --port <PORT>` — port to use (`default`, `admin`)

**Example:**
```bash
z2 deployer rpc -m eth_blockNumber zq2-testnet.yaml
```

### 4.11 ssh
**Purpose:** Run SSH commands on internal network nodes.

**Usage:**
```bash
z2 deployer ssh [OPTIONS] <CONFIG_FILE> [COMMAND]...
```
**Options:**
- `--select` — interactively select nodes

**Example:**
```bash
z2 deployer ssh zq2-testnet.yaml -- "sudo systemctl restart zilliqa.service"
```

### 4.12 backup
**Purpose:** Backup a node's data directory to the persistence bucket.

**Usage:**
```bash
z2 deployer backup [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `-n, --name <NAME>` — backup folder or zip file name
- `--zip` — create a zip file

**Example:**
```bash
z2 deployer backup --name backup-20240704 --zip zq2-testnet.yaml
```

### 4.13 restore
**Purpose:** Restore a node's data directory from a backup.

**Usage:**
```bash
z2 deployer restore [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `-n, --name <NAME>` — backup folder or zip file name
- `--zip` — restore from zip file
- `--no-restart` — do not restart service after restore
- `--max-parallel <N>` — number of nodes to process in parallel (default: 50)

**Example:**
```bash
z2 deployer restore --name backup-20240704 --zip zq2-testnet.yaml
```

### 4.14 reset
**Purpose:** Stop all nodes and clean their `/data` folders.

**Usage:**
```bash
z2 deployer reset [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes

**Example:**
```bash
z2 deployer reset zq2-testnet.yaml
```

### 4.15 restart
**Purpose:** Restart all nodes in the network.

**Usage:**
```bash
z2 deployer restart [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--select` — interactively select nodes

**Example:**
```bash
z2 deployer restart zq2-testnet.yaml
```

### 4.16 monitor
**Purpose:** Monitor network node metrics (e.g., block number, consensus info).

**Usage:**
```bash
z2 deployer monitor [OPTIONS] <CONFIG_FILE>
```
**Options:**
- `--metric <METRIC>` — metric to display (`block-number`, `consensus-info`)
- `--select` — interactively select nodes
- `--follow` — watch for changes

**Example:**
```bash
z2 deployer monitor --metric block-number --follow zq2-testnet.yaml
```

---

## 5. Common Workflows

- **Install a new network:**
  1. Prepare your YAML config file.
  2. Run `z2 deployer install <config.yaml>`
  3. Use `z2 deployer get-config-file` to generate node configs for joining.
- **Upgrade an existing network:**
  1. Update the `versions` in your config file.
  2. Run `z2 deployer upgrade <config.yaml>`
- **Stake management:**
  - Use `deposit`, `deposit-top-up`, `unstake`, and `withdraw` as needed.
- **Backup and restore:**
  - Use `backup` before upgrades or maintenance.
  - Use `restore` to recover from issues.

---

## 6. Troubleshooting & FAQ

- **Q: My config file isn't recognized.**
  - A: Ensure it is valid YAML and matches the expected structure.
- **Q: A node fails during install/upgrade.**
  - A: Check logs with increased verbosity (`-v`). Use `--select` to retry specific nodes.
- **Q: How do I know which nodes are affected?**
  - A: Use `--select` for interactive selection, or check the output summary.
- **Q: Can I use TOML for deployer configs?**
  - A: **No.** Deployer configs must be YAML. TOML is used for chain specs only.

---

## 7. Best Practices & Tips

- Always version-control your deployer YAML configs.
- Use `--select` for granular control during upgrades or troubleshooting.
- Regularly backup node data before major changes.
- Validate YAML files before use.
- Keep your CLI and dependencies up to date.
- Review logs with `-v` or `-vv` for detailed troubleshooting.
- Use the `monitor` subcommand to keep track of network health.

---

For further help, consult your team's onboarding documentation or reach out to the Zilliqa core team.
