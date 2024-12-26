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