variable "name" {
  type     = string
  nullable = false
}

variable "service_account_email" {
  type     = string
  nullable = false
}

variable "network_name" {
  type     = string
  nullable = false
}

variable "subnetwork_name" {
  type     = string
  nullable = false
}

variable "binary_url" {
  type     = string
  nullable = false
}

variable "binary_md5" {
  type     = string
  nullable = false
}

variable "config" {
  type     = string
  nullable = false
}

variable "secret_key" {
  type     = string
  nullable = false
}

variable "node_type" {
  type     = string
  default  = "e2-standard-2"
  nullable = false
}

variable "node_zone" {
  type     = string
  default  = "europe-west2-a"
  nullable = false
}

variable "persistence_url" {
  type     = string
  nullable = true
}

variable "zq_network_name" {
  type     = string
  nullable = false
}

variable "region" {
  description = "The region ID to host the network in"
  type        = string
  default     = "europe-west2"
}


variable "labels" {
  type        = map(string)
  description = "A single-level map/object with key value pairs of metadata labels to apply to the GCP resources. All keys should use underscores and values should use hyphens. All values must be wrapped in quotes."
  nullable    = true
  default     = {}
}

# Add a random suffix to the compute instance names. This ensures that when they are re-created, their `self_link`
# changes and any instance groups containing them are updated.
resource "random_id" "name_suffix" {
  byte_length = 2

  keepers = {
    name                  = var.name
    service_account_email = var.service_account_email
    network_name          = var.network_name
    subnetwork_name       = var.subnetwork_name
    binary_url            = var.binary_url
    binary_md5            = var.binary_md5
    config                = var.config
    secret_key            = var.secret_key
  }
}

resource "google_compute_instance" "this" {
  name                      = "${var.name}-${random_id.name_suffix.hex}"
  machine_type              = var.node_type
  allow_stopping_for_update = true
  zone                      = var.node_zone
  labels                    = merge({ "zq2-network" = var.zq_network_name }, var.labels)

  service_account {
    email = var.service_account_email
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/compute", // REMOVE
    ]
  }

  boot_disk {
    initialize_params {
      size  = 256
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = var.network_name
    subnetwork = var.subnetwork_name
  }

  metadata = {
    "enable-guest-attributes" = "TRUE"
    "enable-osconfig"         = "TRUE"
  }

  metadata_startup_script = <<EOT
#!/bin/bash

set -Eeuxo pipefail

# Install the ops-agent
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
sudo bash add-google-cloud-ops-agent-repo.sh --also-install

# Configure the ops-agent
cat << EOF > /etc/google-cloud-ops-agent/config.yaml
logging:
  receivers:
    zilliqa:
      type: files
      include_paths: [ "/zilliqa.log" ]
  processors:
    json:
      type: parse_json
      time_key: timestamp
      time_format: "%Y-%m-%dT%H:%M:%S.%LZ"
    move_fields:
      type: modify_fields
      fields:
        jsonPayload."logging.googleapis.com/severity":
          move_from: jsonPayload.level
        jsonPayload."logging.googleapis.com/sourceLocation".function:
          move_from: jsonPayload.target
  service:
    pipelines:
      zilliqa:
        receivers: [ zilliqa ]
        processors: [ json, move_fields ]
EOF
sudo systemctl restart google-cloud-ops-agent

# Download and extract the persistence

if [[ -n "${var.persistence_url}" ]]; then
  PERSISTENCE_DIR="${var.data_dir}"
  PERSISTENCE_URL=${var.persistence_url}
  PERSISTENCE_FILENAME="$${PERSISTENCE_URL##*/}"
  mkdir -p "$${PERSISTENCE_DIR}"
  gsutil cp "$${PERSISTENCE_URL}" "$${PERSISTENCE_DIR}/$${PERSISTENCE_FILENAME}"
  cd "$${PERSISTENCE_DIR}" && tar xjf "$${PERSISTENCE_FILENAME}" && rm -f "$${PERSISTENCE_FILENAME}"
fi

# Download the Zilliqa binary
gsutil cp ${var.binary_url} /zilliqa
MD5_SUM=$(echo "${var.binary_md5}" | base64 --decode | hexdump -v -e '/1 "%02x" ')
echo "$MD5_SUM /zilliqa" | md5sum --check -
chmod +x /zilliqa

# Set up our configuration
cat << EOF > /config.toml
${var.config}
EOF

# Set up logrotate to limit the size of the log file
cat << EOF > /etc/logrotate.d/zilliqa.conf
/zilliqa.log
{
    rotate 0
    maxsize 256M
    missingok
}
EOF

# Set up a systemd service for Zilliqa
cat << EOF > /etc/systemd/system/zilliqa.service
[Unit]
Description=Zilliqa Node

[Service]
Type=simple
ExecStart=/zilliqa ${var.secret_key} --log-json
Environment="RUST_LOG=zilliqa=debug"
Environment="RUST_BACKTRACE=1"
StandardOutput=append:/zilliqa.log

[Install]
WantedBy=multi-user.target
EOF

# Start the systemd service
systemctl enable zilliqa.service
systemctl start zilliqa.service
EOT
}

output "id" {
  value = google_compute_instance.this.id
}

output "self_link" {
  value = google_compute_instance.this.self_link
}

output "network_ip" {
  value = google_compute_instance.this.network_interface[0].network_ip
}
