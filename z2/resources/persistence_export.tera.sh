#!/bin/bash

# Directory where checkpoint files are located
CHECKPOINT_DIR="/data/{{ eth_chain_id }}/checkpoints"

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

if is_dir_empty "$CHECKPOINT_DIR"; then  
    # Stop zilliqa service
    if ! sudo systemctl stop zilliqa.service; then
        log_message "Error: Failed to stop zilliqa service"
        exit 1
    fi
    
    # Create persistence export folder name with timestamp
    persistence_export_name="{{ network_name }}-$(date +%Y%m%d%H%M%S)-persistence"
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
else
    log_message "Checkpoint files present in $CHECKPOINT_DIR. Skipping persistence export."
fi