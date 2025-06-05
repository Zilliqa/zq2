# Zilliqa 2.0 Node Provisioning with Ansible

This Ansible playbook automates the provisioning and configuration of Zilliqa 2.0 nodes on Google Cloud Platform (GCP).

```bash
ansible-playbook -i inventory/inventory.gcp.yml playbooks/node_provision.yml -l gcp_zq2_network_zq2_infratest
```

## Prerequisites

- Ansible 2.9 or higher
- Python 3.6 or higher
- SSH access to target nodes
- Google Cloud SDK installed and configured
- Docker registry credentials
- GCP service account with appropriate permissions
- GCP project with enabled APIs:
  - Compute Engine API
  - Cloud Monitoring API
  - Cloud Logging API

## Directory Structure

```
ansible/
├── inventory/
│   ├── gcp_inventory.py      # Dynamic inventory script for GCP
│   └── gcp_inventory.ini     # GCP inventory configuration
├── playbooks/
│   └── node_provision.yml    # Main playbook
├── tasks/
│   ├── common.yml           # Common tasks
│   ├── gcp.yml             # GCP-specific tasks
│   ├── zilliqa.yml         # Zilliqa node tasks
│   ├── monitoring.yml      # Monitoring tasks
│   ├── healthcheck.yml     # Health check tasks
│   └── logrotate.yml      # Log rotation tasks
├── templates/
│   ├── ops-agent-config.yaml.j2  # GCP Ops Agent configuration
│   └── ... (other templates)
├── group_vars/
│   └── all.yml            # Global variables
└── run_playbook.sh        # Helper script to run the playbook
```

## Usage

1. Set up GCP service account key:
```bash
export GCP_SERVICE_ACCOUNT_KEY='{"type": "service_account", ...}'
```

2. Run the playbook:
```bash
./run_playbook.sh --project <project-id> --environment <environment> [--extra-vars <extra-vars>]
```

Example:
```bash
./run_playbook.sh --project my-project --environment prod --extra-vars "zq2_image=zilliqa/z2:latest"
```

## Dynamic Inventory

The playbook uses a dynamic inventory script (`gcp_inventory.py`) that:
- Filters GCP instances by environment tag
- Generates Ansible inventory from filtered instances
- Supports host listing and host details
- Configures SSH access and user information

## Variables

### GCP Configuration
- `project_id`: GCP project ID
- `environment`: Environment name (e.g., dev, prod)
- `gcp_service_account_key`: GCP service account key JSON
- `gcp_persistent_disk_device`: Persistent disk device path
- `gcp_persistent_disk_mount_point`: Persistent disk mount point
- `enable_gcp_monitoring`: Enable GCP monitoring (default: true)

### Docker Configuration
- `docker_image`: Zilliqa 2.0 Docker image
- `otterscan_image`: Otterscan Docker image
- `spout_image`: Spout Docker image
- `stats_dashboard_image`: Stats Dashboard Docker image
- `stats_agent_image`: Stats Agent Docker image
- `zq2_metrics_image`: Zilliqa 2.0 metrics Docker image

### Node Configuration
- `node_role`: Node role (default: validator)
- `chain_name`: Chain name
- `log_level`: Log level (default: info)

### API Configuration
- `private_api`: Private API type (default: metrics)
- `zq2_metrics_enabled`: Enable Zilliqa 2.0 metrics

### Persistence Configuration
- `persistence_url`: Persistence data URL
- `checkpoint_url`: Checkpoint data URL

### KMS Configuration
- `enable_kms`: Enable KMS (default: false)
- `kms_project_id`: KMS project ID

## Services

The playbook installs and configures the following services:

1. Zilliqa 2.0 Node
   - Core node service
   - Configuration management
   - Persistence handling

2. Otterscan (optional)
   - Block explorer
   - Transaction monitoring
   - Contract interaction

3. Spout (optional)
   - Faucet service
   - Token distribution
   - Network testing

4. Stats Dashboard (optional)
   - Performance monitoring
   - Network statistics
   - Node health metrics

5. Stats Agent (optional)
   - Metrics collection
   - Data aggregation
   - Monitoring integration

6. Node Exporter
   - System metrics
   - Resource monitoring
   - Performance tracking

7. Process Exporter
   - Process monitoring
   - Service health checks
   - Resource usage tracking

8. Health Check Service
   - Service monitoring
   - Automatic recovery
   - Status reporting

## Monitoring

The playbook configures comprehensive monitoring using:

1. GCP Ops Agent
   - Log collection
   - Metric aggregation
   - Cloud monitoring integration

2. Prometheus Exporters
   - Node Exporter
   - Process Exporter
   - Zilliqa metrics

3. Log Management
   - Centralized logging
   - Log rotation
   - Error tracking

## Health Checks

The health check service:
- Monitors all running services
- Checks Docker container status
- Verifies API endpoints
- Reports service health
- Triggers automatic recovery

## Log Rotation

Log rotation is configured for all services with:
- Daily rotation
- 7-day retention
- Compression
- Size limits
- Post-rotation commands

## Security

The playbook implements several security measures:

1. Service Isolation
   - Separate service accounts
   - Minimal permissions
   - Network isolation

2. Log Management
   - Secure log storage
   - Access control
   - Audit trails

3. Health Monitoring
   - Service checks
   - Security scanning
   - Vulnerability detection

4. KMS Integration
   - Secure key management
   - Encryption at rest
   - Access control

5. File Permissions
   - Strict access control
   - Secure defaults
   - Regular audits

6. Service Hardening
   - Minimal privileges
   - Secure defaults
   - Regular updates

## Troubleshooting

1. Check service status:
```bash
systemctl status zilliqa
systemctl status healthcheck
```

2. View logs:
```bash
journalctl -u zilliqa
journalctl -u healthcheck
```

3. Check GCP monitoring:
```bash
gcloud monitoring dashboards list
```

4. Verify disk mounts:
```bash
mount | grep /data
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 