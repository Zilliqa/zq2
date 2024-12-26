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

# Start the backup process
start_time=$(date +%s)

if is_dir_empty "$CHECKPOINT_DIR"; then  
    # Stop zilliqa service
    log_message "Stopping zilliqa service"
    if ! sudo systemctl stop zilliqa.service; then
        log_message "Error: Failed to stop zilliqa service"
        exit 1
    fi
    
    # Create backup filename with timestamp
    backup_name="{{ network_name }}-$(date +%Y%m%d%H%M%S)-persistence"
    log_message "Creating persitence export: $backup_name"
    
    # Create zip archive
    if ! zip -r "/tmp/$backup_name.zip" /data; then
        log_message "Error: Failed to create backup archive"
        # Start zilliqa service before exiting
        sudo systemctl start zilliqa.service
        exit 1
    fi
    
    # Upload to GCS
    log_message "Uploading backup to GCS bucket"
    if ! gsutil -m cp "/tmp/$backup_name.zip" "$GCS_BUCKET/"; then
        log_message "Error: Failed to upload backup to GCS"
        # Clean up and start service before exiting
        rm -f "/tmp/$backup_name.zip"
        sudo systemctl start zilliqa.service
        exit 1
    fi
    
    # Clean up temporary file
    rm -f "/tmp/$backup_name.zip"
    
    # Start zilliqa service
    log_message "Starting zilliqa service"
    if ! sudo systemctl start zilliqa.service; then
        log_message "Error: Failed to start zilliqa service"
        exit 1
    fi
    
    # Calculate and log total execution time
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    log_message "Persitence export completed successfully in $duration seconds"
else
    log_message "Checkpoint files present in $CHECKPOINT_DIR. Skipping persitence export."
fi