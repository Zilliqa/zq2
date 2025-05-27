#!/usr/bin/env python3

import os
import time
import json
import shutil
import logging
import requests
import subprocess
from datetime import datetime
from pathlib import Path
from google.cloud import storage

# Configuration
NETWORK_NAME = "{{ network_name }}"
ETH_CHAIN_ID = "{{ eth_chain_id }}"
DATA_DIR = "/data"
TEMP_DIR = "/tmp"
LOG_NAME = f"{NETWORK_NAME}-persistence-backup-log"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(LOG_NAME)

def get_block_number():
    """Get the current block number from the local node."""
    try:
        response = requests.post(
            "http://localhost:4201",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_blockNumber"
            },
            headers={"content-type": "application/json"},
            timeout=10
        )
        result = response.json()
        if "result" in result:
            return int(result["result"], 16)
        raise ValueError(f"Invalid response: {result}")
    except Exception as e:
        logger.error(f"Failed to get block number: {e}")
        return None

def manage_zilliqa_service(action):
    """Manage the Zilliqa service (start/stop)."""
    try:
        subprocess.run(
            ["sudo", "systemctl", action, "zilliqa.service"],
            check=True,
            capture_output=True
        )
        logger.info(f"Successfully {action}ed Zilliqa service")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to {action} Zilliqa service: {e.stderr.decode()}")
        return False

def create_backup(block_number):
    """Create a backup of the data directory."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    backup_name = f"{ETH_CHAIN_ID}-{block_number}-{timestamp}"
    backup_path = Path(TEMP_DIR) / backup_name
    
    try:
        # Create a fresh backup directory
        if backup_path.exists():
            shutil.rmtree(backup_path)
        shutil.copytree(DATA_DIR, backup_path)
        logger.info(f"Successfully created backup at {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return None

def upload_to_gcs(backup_path):
    """Upload the backup to Google Cloud Storage."""
    try:
        client = storage.Client()
        bucket = client.get_bucket(f"{NETWORK_NAME}-persistence")
        
        # Upload all files in the backup directory
        for local_path in backup_path.rglob('*'):
            if local_path.is_file():
                relative_path = local_path.relative_to(backup_path)
                blob_path = f"{backup_path.name}/{relative_path}"
                blob = bucket.blob(blob_path)
                blob.upload_from_filename(str(local_path))
        
        logger.info(f"Successfully uploaded backup to GCS: {backup_path.name}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload to GCS: {e}")
        return False

def cleanup(backup_path):
    """Clean up the temporary backup directory."""
    try:
        if backup_path and backup_path.exists():
            shutil.rmtree(backup_path)
            logger.info(f"Successfully cleaned up {backup_path}")
    except Exception as e:
        logger.error(f"Failed to clean up {backup_path}: {e}")

def main():
    try:
        while True:
            block_number = get_block_number()
            if block_number is None:
                logger.error("Could not get block number, retrying in 60 seconds")
                time.sleep(60)
                continue

            # Check if we should create a backup (every 10800 blocks)
            if block_number % 10800 == 0:
                logger.info(f"Starting backup at block {block_number}")
                
                # Stop Zilliqa service
                if not manage_zilliqa_service("stop"):
                    continue

                # Create backup
                backup_path = create_backup(block_number)
                
                # Start Zilliqa service immediately after copy
                manage_zilliqa_service("start")

                if backup_path:
                    # Upload to GCS
                    if upload_to_gcs(backup_path):
                        # Clean up only if upload was successful
                        cleanup(backup_path)
                    else:
                        logger.error("Backup remains in temp directory due to upload failure")
                
                # Wait for next check (approximately 3 hours at 1 block/sec)
                time.sleep(10800)
            else:
                # Check every minute
                time.sleep(60)

    except TimeoutError:
        logger.error("Another instance is already running")
        exit(1)
    except KeyboardInterrupt:
        logger.info("Backup service stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        exit(1)

if __name__ == "__main__":
    main() 