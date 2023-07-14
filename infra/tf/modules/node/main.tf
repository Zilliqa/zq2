variable "name" {
  type = string
  nullable = false
}

variable "service_account_email" {
    type = string
    nullable = false
}

variable "network_name" {
    type = string
    nullable = false
}

variable "subnetwork_name" {
    type = string
    nullable = false
}

variable "binary_url" {
    type = string
    nullable = false
}

variable "config" {
    type = string
    nullable = false
}

variable "secret_key" {
    type = string
    nullable = false
}

# Add a random suffix to the compute instance names. This ensures that when they are re-created, their `self_link`
# changes and any instance groups containing them are updated.
resource "random_id" "name_suffix" {
  byte_length = 2

  keepers = {
    name = var.name
    service_account_email = var.service_account_email
    network_name = var.network_name
    subnetwork_name = var.subnetwork_name
    binary_url = var.binary_url
    config = var.config
    secret_key = var.secret_key
  }
}

resource "google_compute_instance" "this" {
  name                      = "${var.name}-${random_id.name_suffix.hex}"
  machine_type              = "e2-standard-2"
  allow_stopping_for_update = true

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
      size = 256
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

gsutil cp ${var.binary_url} /zilliqa
chmod +x /zilliqa

cat << EOF > /config.toml
${var.config}
EOF

cat << EOF > /etc/systemd/system/zilliqa.service
[Unit]
Description=Zilliqa 2 Node

[Service]
Type=simple
ExecStart=/zilliqa ${var.secret_key}
Environment="RUST_LOG=zilliqa=debug"
Environment="RUST_BACKTRACE=1"

[Install]
WantedBy=multi-user.target
EOF

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
