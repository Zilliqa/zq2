#!/usr/bin/env python3

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from google.cloud import secretmanager
from google.api_core import exceptions
from typing import Dict, Any, Optional

def parse_args():
    parser = argparse.ArgumentParser(description="Backup GCP secrets to 1Password")
    parser.add_argument("--project-id", required=True, help="GCP project ID")
    parser.add_argument("--label-key", default="zq2-network", help="Label key to match")
    parser.add_argument("--label-value", required=True, help="Label value to match")
    parser.add_argument("--vault", required=True, help="1Password vault name to store secrets")
    parser.add_argument('--dry-run', action='store_true', help='Simulate actions without making any changes')
    parser.add_argument('--force', action='store_true', help='Skip confirmation for existing secrets')
    parser.add_argument('--kms', action='store_true', help='Enable KMS decryption for keys')
    return parser.parse_args()

def get_kms_project_id(project_id: str) -> str:
    if project_id.startswith("prj-p"):
        return "prj-p-kms-2vduab0g"
    else:
        return "prj-d-kms-tw1xyxbh"

def decrypt_with_kms(ciphertext: str, project_id: str, chain_name: str, secret_name: str, dry_run: bool = False) -> str:
    if dry_run:
        print(f"[DRY-RUN] Would decrypt secret '{secret_name}' using KMS key in project '{project_id}', keyring 'kms-{chain_name}', key '{secret_name}'")
        return "DRYRUN_DECRYPTED_KEY=="

    kms_project_id = get_kms_project_id(project_id)
    
    # Write ciphertext to a temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as ctf:
        ctf.write(base64.b64decode(ciphertext))
        ctf.flush()
        plaintext_file = ctf.name + ".pt"
        
        cmd = [
            "gcloud", "kms", "decrypt",
            f"--project={kms_project_id}",
            "--location=global",
            f"--keyring=kms-{chain_name}",
            f"--key={secret_name}",
            f"--ciphertext-file={ctf.name}",
            f"--plaintext-file={plaintext_file}"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"KMS decryption failed: {result.stderr}")
            
        # Read plaintext
        with open(plaintext_file, 'r') as pf:
            plaintext = pf.read()
            
        subprocess.run(["rm", ctf.name, plaintext_file])
        return plaintext

def create_1password_item(title: str, value: str, vault: str, dry_run: bool = False) -> bool:
    # Create a temporary file with the JSON template
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
        template = {
            "title": title,
            "category": "PASSWORD",
            "fields": [
                {
                    "id": "password",
                    "type": "CONCEALED",
                    "purpose": "PASSWORD",
                    "label": "password",
                    "value": value
                }
            ]
        }
        json.dump(template, tmp)
        tmp.flush()
        
        cmd = [
            "op", "item", "create",
            "--vault", vault,
            "--template", tmp.name
        ]
        
        if dry_run:
            cmd.append("--dry-run")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        subprocess.run(["rm", tmp.name])
        
        if result.returncode != 0:
            print(f"Error creating 1Password item: {result.stderr}", file=sys.stderr)
            return False
            
        if dry_run:
            print(f"[DRY-RUN] Would create 1Password item '{title}' in vault '{vault}'")
            print(result.stdout)
            
        return True

def backup_secrets_to_1password(project_id: str, label_key: str, label_value: str, vault: str, dry_run: bool = False, force: bool = False, kms_enabled: bool = False):
    """
    Backup all secrets in a GCP project that have a specific label to 1Password.
    
    Args:
        project_id (str): The GCP project ID
        label_key (str): The label key to match
        label_value (str): The label value to match
        vault (str): The 1Password vault name to store secrets
        dry_run (bool): If True, only simulate the actions
        force (bool): If True, skip confirmation for existing secrets
        kms_enabled (bool): If True, decrypt secrets using KMS before backup
    """
    # Initialize the Secret Manager client
    client = secretmanager.SecretManagerServiceClient()
    
    # Construct the parent project path
    parent = f"projects/{project_id}"
    
    try:
        # List all secrets in the project
        secrets = client.list_secrets(request={"parent": parent})
        
        backed_up_count = 0
        for secret in secrets:
            # Check if the secret has the specified label
            if secret.labels.get(label_key) == label_value:
                try:
                    # Get the latest version of the secret
                    secret_name = secret.name
                    version = client.access_secret_version(request={"name": f"{secret_name}/versions/latest"})
                    secret_value = version.payload.data.decode("UTF-8")
                    
                    # Decrypt with KMS if enabled
                    if kms_enabled and secret_name.endswith("-enckey"):
                        secret_value = decrypt_with_kms(
                            secret_value,
                            project_id,
                            label_value,
                            secret_name.split("/")[-1].replace("-enckey", ""),
                            dry_run
                        )
                    
                    # Create 1Password item
                    if not dry_run:
                        if not force:
                            confirmation = input(f"Confirm backup {secret_name} to 1Password vault '{vault}'? (y/n): ")
                            if confirmation.lower() != 'y':
                                print(f"Skipping backup {secret_name}")
                                continue
                    
                    # Create 1Password item
                    if create_1password_item(secret_name.split("/")[-1], secret_value, vault, dry_run):
                        print(f"Backed up secret: {secret_name}")
                        backed_up_count += 1
                    else:
                        print(f"Failed to backup secret: {secret_name}")
                        
                except exceptions.NotFound:
                    print(f"Secret {secret_name} not found")
                except exceptions.PermissionDenied:
                    print(f"Permission denied to access secret: {secret_name}")
                except Exception as e:
                    print(f"Error backing up secret {secret_name}: {str(e)}")
        
        print(f"\nTotal secrets backed up: {backed_up_count}")
        
    except exceptions.PermissionDenied:
        print(f"Permission denied to list secrets in project {project_id}")
    except Exception as e:
        print(f"Error listing secrets: {str(e)}")

def main():
    args = parse_args()
    
    print(f"Backing up secrets in project {args.project_id} with label {args.label_key}={args.label_value} to 1Password vault '{args.vault}'")
    backup_secrets_to_1password(
        args.project_id,
        args.label_key,
        args.label_value,
        args.vault,
        args.dry_run,
        args.force,
        args.kms
    )

if __name__ == "__main__":
    main() 