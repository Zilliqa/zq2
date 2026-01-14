# Zilliqa 2.0 Network Deployment

This repository contains Ansible playbooks and Python scripts for deploying and managing Zilliqa 2.0 networks on Google Cloud Platform (GCP). It provides a complete solution for setting up validator nodes, API nodes, and supporting services.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Deployment Process](#deployment-process)
- [Network Management](#network-management)
- [Monitoring and Maintenance](#monitoring-and-maintenance)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Tools

- Python 3.9+
- Ansible 2.9+
- Google Cloud SDK
- Docker
- Terraform (for infrastructure provisioning)

### GCP Requirements

- GCP project with billing enabled
- Service account with the following roles:
  - Compute Admin
  - Secret Manager Admin
  - Cloud KMS Admin
  - Storage Admin
  - IAM Admin
- Enabled APIs:
  - Compute Engine API
  - Cloud KMS API
  - Secret Manager API
  - Cloud Storage API
  - Cloud Monitoring API
  - Cloud Logging API

### Ansible Requirements

- Install Ansible collection requirements:
```bash
ansible-galaxy collection install -r requirements.yml
```

### Authentication Setup

- Set up GCP authentication:
```bash
gcloud auth application-default login
gcloud config set project <your-project-id>
```

## Project Structure

```
infra/
├── ansible/
│   ├── playbooks/              # Ansible playbooks
│   │   ├── install_zilliqa.yml    # Main node installation
│   │   ├── install_monitoring.yml # Monitoring setup
│   │   ├── install_spout.yml      # Faucet service
│   │   ├── install_otterscan.yml  # Block explorer
│   │   └── configure_*.yml        # Various configuration playbooks
│   │
│   ├── templates/              # Jinja2 templates
│   │   ├── zilliqa.sh.j2         # Node startup script
│   │   ├── zilliqa.service.j2    # Systemd service
│   │   └── *.j2                 # Other configuration templates
│   │
│   ├── group_vars/            # Group variables
│   │   ├── all.yml              # Global variables
│   │   └── network_*/           # Network-specific variables
│   │
│   ├── inventory.gcp.yml      # GCP inventory configuration
│   └── ansible.cfg            # Ansible configuration
│
├── scripts/                   # Python scripts
│   ├── generate_keys.py       # Key generation
│   ├── generate_keys_config.py # Key configuration
│   └── setenv                 # Environment setup
│
└── terraform/                 # Infrastructure as Code
    ├── main.tf               # Main Terraform configuration
    ├── variables.tf          # Variable definitions
    └── outputs.tf            # Output definitions
```

## Configuration

### Node Configuration
Configure node-specific variables in `group_vars/network_*/all.yml`:

```yaml
# Node Configuration
chain_name: "zq2-devnet"
eth_chain_id: 33101
log_level: "info"
dns_subdomain: "zq2-devnet.zilstg.dev"

# Docker Configuration
zq2_image: "asia-docker.pkg.dev/your-project/zq2:latest"
```

## Deployment Process

### 1. Key Generation

If you want to remove the previously generated key:

```bash
# Generate stats dashboard secret
python scripts/delete_gcp_secrets.py --project-id=your-project --label-key "zq2-network" --label-value "network_name" --force
```

otherwise:

```bash
# Generate node keys
python scripts/generate_private_keys.py network.yaml --project-id=your-project

# Generate stats dashboard secret
python scripts/generate_stats_key.py network.yaml --project-id=your-project

# Generate genesis key
python scripts/generate_genesis_key.py network.yaml --project-id=your-project
```

for example:
```bash
python3 scripts/delete_gcp_secrets.py --project-id prj-d-zq2-devnet-c83bkpsd --label-value "zq2-infratest" --force

python3 scripts/generate_private_keys.py --project-id prj-d-zq2-devnet-c83bkpsd ../../zq2-infratest.yaml

python3 scripts/generate_stats_key.py --project-id prj-d-zq2-devnet-c83bkpsd ../../zq2-infratest.yaml

python3 scripts/generate_genesis_key.py --project-id prj-d-zq2-devnet-c83bkpsd ../../zq2-infratest.yaml
```

To backup the just created credentials, please run:
```bash
python3 scripts/backup_secrets.py --project-id prj-d-zq2-devnet-c83bkpsd --label-value "zq2-infratest" --vault "<VALUE_NAME>" --force
```

### 2. Node Deployment

Deploy all the nodes:

```bash
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/node_provision.yml
```

### 3. (Alternative) Deploy single components, for example:
```bash
# Install monitoring
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/install_monitoring.yml

# Install block explorer
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/install_otterscan.yml

# Install faucet
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/install_spout.yml
```

## Network Management

### Adding New Nodes
1. Update inventory:
```bash
# Print the inventory as list
ansible-inventory -i inventory.gcp.yml --list 

# Print the inventory as graph
ansible-inventory -i inventory.gcp.yml --graph
```

2. Deploy node:
```bash
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/install_zilliqa.yml --limit role_validator
```

### Updating Nodes
```bash
# Update node software
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/install_zilliqa.yml --limit role_validator \
  -e "zq2_image=asia-docker.pkg.dev/your-project/zq2:new-version"
```

### Restore Persistence Snapshot

In the `all.yml` file for the network you want to restore, set the `persistence_snapshot_id` variable to reference the desired snapshot. If `persistence_snapshot_id` is not set, the latest snapshot backup will be used.

Then run the playbook:

```bash
# Restore the GCP snapshot backup in a node /data disk
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/restore_persistence_snapshot.yml --limit role_api
```

### Upgrade Ubuntu
```bash
# Update Ubuntu version to 24.04 for api nodes
ansible-playbook -i inventory.gcp.yml -l network_zq2_infratest,localhost playbooks/upgrade_ubuntu.yml --limit role_api
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request
