#!/bin/bash

# GCS bucket where the persistence will be exported
GCS_BUCKET="gs://{{ network_name }}-persistence"

# Log name in Google Cloud Logging
LOG_NAME="{{ network_name }}-persistence-export-cron-log"

# Function to log messages to Google Cloud Logging
log_message() {
    local message="$1"
    logger -t "$LOG_NAME" "$message"
}

# Function to check if directory is empty
is_dir_empty() {
    local dir="$1"
    [ -z "$(ls -A $dir)" ]
}

# Start the persistence export process
start_time=$(date +%s)

# Stop zilliqa service
if ! sudo systemctl stop zilliqa.service; then
    log_message "Error: Failed to stop zilliqa service"
    exit 1
fi

# Create persistence export folder name with timestamp
persistence_export_name="{{ eth_chain_id }}-persistence-$(date +%Y%m%d)-$(date +%H%M)"
log_message "Creating persistence export: $persistence_export_name"

# Upload to GCS
if ! gsutil -m cp -r /data "$GCS_BUCKET/$persistence_export_name/"; then
    log_message "Error: Failed to upload data to GCS"
    sudo systemctl start zilliqa.service
    exit 1
fi

# Start zilliqa service
if ! sudo systemctl start zilliqa.service; then
    log_message "Error: Failed to start zilliqa service"
    exit 1
fi

# Calculate and log total execution time
end_time=$(date +%s)
duration=$((end_time - start_time))
log_message "Persistence export completed successfully in $duration seconds"

# Keep only the most recent 30 checkpoints in the GCS bucket
gsutil ls -d "$GCS_BUCKET/{{ eth_chain_id }}-persistence-*/" | sort -r | tail -n +101 | awk '{print $1}' | xargs -I {} gsutil rm -rfa {}
log_message "Cleanup completed"
