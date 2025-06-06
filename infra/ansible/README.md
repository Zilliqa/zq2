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

### Authentication Setup
1. Set up GCP authentication:
```bash
gcloud auth application-default login
gcloud config set project <your-project-id>
```

2. Set service account key:
```bash
export GCP_SERVICE_ACCOUNT_KEY='{"type": "service_account", ...}'
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

### Network Configuration
Create a YAML file (e.g., `network.yaml`) with the following structure:

```yaml
name: "zq2-devnet"
eth_chain_id: 33101
api_servers:
  - "https://api.zq2-devnet.zilstg.dev"
genesis_fork:
  block: 0
  version: "0.1.0"
forks:
  - block: 1000
    version: "0.2.0"
```

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

### 1. Infrastructure Setup
```bash
# Initialize Terraform
cd terraform
terraform init

# Create infrastructure
terraform apply -var="project_id=your-project" -var="network_name=zq2-devnet"
```

### 2. Key Generation
```bash
# Generate node keys
python scripts/generate_keys.py network.yaml --project-id=your-project

# Generate key configuration
python scripts/generate_keys_config.py network.yaml --project-id=your-project
```

### 3. Node Deployment
```bash
# Deploy validator nodes
ansible-playbook -i inventory.gcp.yml playbooks/install_zilliqa.yml \
  -e "target_group=role_validator" \
  -e "chain_name=zq2-devnet"

# Deploy API nodes
ansible-playbook -i inventory.gcp.yml playbooks/install_zilliqa.yml \
  -e "target_group=role_api" \
  -e "chain_name=zq2-devnet"
```

### 4. Supporting Services
```bash
# Install monitoring
ansible-playbook -i inventory.gcp.yml playbooks/install_monitoring.yml

# Install block explorer
ansible-playbook -i inventory.gcp.yml playbooks/install_otterscan.yml

# Install faucet
ansible-playbook -i inventory.gcp.yml playbooks/install_spout.yml
```

## Network Management

### Adding New Nodes
1. Update inventory:
```bash
ansible-inventory --list -i inventory.gcp.yml
```

2. Deploy node:
```bash
ansible-playbook -i inventory.gcp.yml playbooks/install_zilliqa.yml \
  -e "target_group=role_validator" \
  -e "chain_name=zq2-devnet"
```

### Updating Nodes
```bash
# Update node software
ansible-playbook -i inventory.gcp.yml playbooks/install_zilliqa.yml \
  -e "target_group=role_validator" \
  -e "zq2_image=asia-docker.pkg.dev/your-project/zq2:new-version"
```

### Node Maintenance
```bash
# Stop node
ansible-playbook -i inventory.gcp.yml playbooks/maintenance.yml \
  -e "action=stop" \
  -e "target_group=role_validator"

# Start node
ansible-playbook -i inventory.gcp.yml playbooks/maintenance.yml \
  -e "action=start" \
  -e "target_group=role_validator"
```

## Monitoring and Maintenance

### Health Checks
```bash
# Check node health
ansible-playbook -i inventory.gcp.yml playbooks/configure_healthcheck.yml

# View health status
curl http://node-ip:8000/health
```

### Log Management
```bash
# View node logs
ansible-playbook -i inventory.gcp.yml playbooks/view_logs.yml \
  -e "target_group=role_validator"

# Configure log rotation
ansible-playbook -i inventory.gcp.yml playbooks/configure_logrotate.yml
```

### Metrics Collection
```bash
# Install metrics collection
ansible-playbook -i inventory.gcp.yml playbooks/install_stats_agent.yml

# View metrics dashboard
open https://stats.zq2-devnet.zilstg.dev
```

## Troubleshooting

### Common Issues

1. Node Not Starting
```bash
# Check service status
ansible-playbook -i inventory.gcp.yml playbooks/check_status.yml \
  -e "target_group=role_validator"

# View logs
ansible-playbook -i inventory.gcp.yml playbooks/view_logs.yml \
  -e "target_group=role_validator"
```

2. KMS Issues
```bash
# Verify KMS configuration
ansible-playbook -i inventory.gcp.yml playbooks/verify_kms.yml

# Check key access
gcloud kms keys list --keyring=kms-zq2-devnet --location=global
```

3. Network Connectivity
```bash
# Check network connectivity
ansible-playbook -i inventory.gcp.yml playbooks/check_network.yml

# Verify API endpoints
curl https://api.zq2-devnet.zilstg.dev/health
```

### Debugging Tools

1. Node Debugging
```bash
# Enable debug logging
ansible-playbook -i inventory.gcp.yml playbooks/configure_logging.yml \
  -e "log_level=debug"

# Collect debug information
ansible-playbook -i inventory.gcp.yml playbooks/collect_debug.yml
```

2. Network Debugging
```bash
# Check network status
ansible-playbook -i inventory.gcp.yml playbooks/check_network.yml

# Verify node synchronization
ansible-playbook -i inventory.gcp.yml playbooks/check_sync.yml
```

## Security Considerations

1. Key Management
- Use KMS for key encryption
- Rotate keys regularly
- Implement access controls

2. Network Security
- Use IAP for SSH access
- Implement firewall rules
- Enable VPC service controls

3. Monitoring
- Enable audit logging
- Monitor access patterns
- Set up alerts

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 