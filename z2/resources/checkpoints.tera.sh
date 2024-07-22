#!/bin/bash

# Directory where checkpoint files are located
CHECKPOINT_DIR="/data/{{ eth_chain_id }}/checkpoints"

# GCS bucket where checkpoints will be uploaded
GCS_BUCKET="gs://{{ network_name }}-checkpoint/data/"

# Log name in Google Cloud Logging
LOG_NAME="{{ network_name }}-checkpoint-cron-log"

# Function to log messages to Google Cloud Logging
log_message() {
    local message="$1"
    logger -t "$LOG_NAME" "$message"
}

# Watch for completed checkpoint files (excluding .part files)
find "$CHECKPOINT_DIR" -type f ! -name '*.part' -printf "%T@ %p\n" | sort -n | awk '{print $2}' | while IFS= read -r CHECKPOINT_FILE; do
    log_message "Processing $CHECKPOINT_FILE"

    # Copy the checkpoint file to GCS
    if gsutil cp "$CHECKPOINT_FILE" "$GCS_BUCKET"; then
        log_message "Uploaded $CHECKPOINT_FILE to GCS"

        # Delete the file from the local directory
        rm "$CHECKPOINT_FILE"
        log_message "Deleted $CHECKPOINT_FILE from local directory"
    else
        log_message "Failed to upload $CHECKPOINT_FILE to GCS"
    fi
done

# Keep only the most recent 50 checkpoints in the GCS bucket
gsutil ls "$GCS_BUCKET" | sort | head -n -50 | xargs -I {} gsutil rm {}
log_message "Cleanup completed"

# Copy the most recent checkpoint as latest
gsutil ls -l $GCS_BUCKET | grep -v "TOTAL" | grep -v latest | sort -k 2 -n |  tail -1 | awk '{print $3}' | xargs -I {} gsutil cp {} "${GCS_BUCKET}latest"
log_message "Updated latest checkpoint"
