#!/usr/bin/env python3

import argparse
import sys
import yaml
import json
import os
import subprocess
import tempfile
from secret_key import SecretKey
from typing import List, Dict, Any
from eth_keys import keys  # pip install eth-keys
from convert_key import convert_key_rust

def parse_args():
    parser = argparse.ArgumentParser(description='Generate genesis key for Zilliqa 2 network')
    parser.add_argument('config_file', help='Path to network YAML configuration')
    parser.add_argument("--project-id", required=True, help="GCP project ID")
    parser.add_argument('--force', action='store_true', help='Overwrite existing key')
    parser.add_argument('--dry-run', action='store_true', help='Simulate actions without making any changes')
    parser.add_argument('--kms', action='store_true', help='Enable KMS encryption for keys')
    return parser.parse_args()

def load_config(config_path: str):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def get_secret_name(chain_name: str, kms_enabled: bool) -> str:
    return f"{chain_name}-genesis-enckey" if kms_enabled else f"{chain_name}-genesis"

def get_address_secret_name(chain_name: str) -> str:
    return f"{chain_name}-genesis-address"

def get_kms_project_id(project_id: str) -> str:
    if project_id.startswith("prj-p"):
        return "prj-p-kms-2vduab0g"
    else:
        return "prj-d-kms-tw1xyxbh"

def encrypt_with_kms(plaintext: str, project_id: str, chain_name: str, dry_run: bool = False) -> str:
    if dry_run:
        print(f"[DRY-RUN] Would encrypt genesis key using KMS key in project '{project_id}', keyring 'kms-{chain_name}', key 'genesis'")
        return "DRYRUN_ENCRYPTED_KEY=="
    kms_project_id = get_kms_project_id(project_id)
    import tempfile, base64
    with tempfile.NamedTemporaryFile(delete=False) as ptf:
        ptf.write(plaintext.encode())
        ptf.flush()
        ciphertext_file = ptf.name + ".enc"
        cmd = [
            "gcloud", "kms", "encrypt",
            f"--project={kms_project_id}",
            "--location=global",
            f"--keyring=kms-{chain_name}",
            f"--key={chain_name}-genesis",
            f"--plaintext-file={ptf.name}",
            f"--ciphertext-file={ciphertext_file}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"KMS encryption failed: {result.stderr}")
        with open(ciphertext_file, 'rb') as cf:
            ciphertext = cf.read()
        os.remove(ptf.name)
        os.remove(ciphertext_file)
        return base64.b64encode(ciphertext).decode()

def create_secret_in_gcp(secret_name: str, value: str, project_id: str, labels: dict, force: bool = False, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"[DRY-RUN] Would create secret '{secret_name}' in project '{project_id}' with labels {labels} (force={force}) and value (hidden)")
        return True
    check_cmd = ["gcloud", "secrets", "describe", secret_name, "--project", project_id]
    result = subprocess.run(check_cmd, capture_output=True, text=True)
    if result.returncode == 0:
        if not force:
            print(f"Secret '{secret_name}' already exists. Use --force to overwrite.")
            return True
        del_cmd = ["gcloud", "secrets", "delete", secret_name, "--project", project_id, "--quiet"]
        subprocess.run(del_cmd, capture_output=True)
    create_cmd = [
        "gcloud", "secrets", "create", secret_name,
        "--project", project_id,
        "--replication-policy", "automatic"
    ]
    for k, v in labels.items():
        create_cmd.extend(["--labels", f"{k}={v}"])
    create_result = subprocess.run(create_cmd, capture_output=True, text=True)
    if create_result.returncode != 0:
        print(f"Error creating secret: {create_result.stderr}", file=sys.stderr)
        return False
    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as tmp:
        tmp.write(value)
        tmp.flush()
        version_cmd = [
            "gcloud", "secrets", "versions", "add", secret_name,
            "--project", project_id,
            "--data-file", os.path.abspath(tmp.name)
        ]
        version_result = subprocess.run(version_cmd, capture_output=True, text=True)
        os.remove(tmp.name)
        return version_result.returncode == 0

def grant_secret_access(secret_name: str, project_id: str, service_account: str, dry_run: bool = False) -> bool:
    if not service_account:
        return False
    if dry_run:
        print(f"[DRY-RUN] Would grant roles/secretmanager.secretAccessor on '{secret_name}' to {service_account}")
        return True
    add_iam_cmd = [
        "gcloud", "secrets", "add-iam-policy-binding", secret_name,
        "--project", project_id,
        "--member", f"serviceAccount:{service_account}",
        "--role", "roles/secretmanager.secretAccessor"
    ]
    result = subprocess.run(add_iam_cmd, capture_output=True, text=True)
    return result.returncode == 0

# --- GCP Node Discovery ---
def discover_gcp_nodes(chain_name: str, project_id: str) -> List[Dict[str, Any]]:
    # Use gcloud CLI to list instances with the correct label
    cmd = [
        'gcloud', 'compute', 'instances', 'list',
        '--project', project_id,
        '--filter', f'labels.zq2-network={chain_name}',
        '--format', 'json'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running gcloud: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    instances = json.loads(result.stdout)
    nodes = []
    print(f"Found {len(instances)} instances")
    for inst in instances:
        node = {
            'project_id': inst['zone'].split('/')[-3],
            'zone': inst['zone'].split('/')[-1],
            'name': inst['name'],
            'external_address': inst.get('networkInterfaces', [{}])[0].get('accessConfigs', [{}])[0].get('natIP'),
            'labels': inst.get('labels', {}),
            'service_account': inst.get('serviceAccounts', [{}])[0].get('email'),
        }
        nodes.append(node)
    return nodes

def filter_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Include only nodes with role == 'apps'."""
    return [n for n in nodes if n.get('labels', {}).get('role') == 'apps']

if __name__ == "__main__":
    args = parse_args()
    config = load_config(args.config_file)
    chain_name = config.get('name')
    if not chain_name:
        print("Could not determine chain/network name from config.", file=sys.stderr)
        sys.exit(1)
    project_id = args.project_id
    print(f"Generating genesis key for network '{chain_name}'...")

    # Generate key
    secret_key = SecretKey.new()
    key_hex = secret_key.to_hex()

    # Get secret names
    secret_name = get_secret_name(chain_name, args.kms)
    address_secret_name = get_address_secret_name(chain_name)
    genesis_address = convert_key_rust(key_hex, config.get('eth_chain_id'))['control_address']

    # Encrypt with KMS if enabled
    if args.kms:
        try:
            key_hex = encrypt_with_kms(key_hex, project_id, chain_name, args.dry_run)
        except Exception as e:
            print(f"Error encrypting key: {e}", file=sys.stderr)
            sys.exit(1)

    # Store genesis key
    key_labels = {"role": "genesis", "zq2-network": chain_name}
    if not create_secret_in_gcp(secret_name, key_hex, project_id, key_labels, args.force, args.dry_run):
        print("Failed to create genesis key secret.", file=sys.stderr)
        sys.exit(1)

    nodes = discover_gcp_nodes(chain_name, project_id)

    address_labels = {"role": "genesis-address", "zq2-network": chain_name}
    if not create_secret_in_gcp(address_secret_name, genesis_address, project_id, address_labels, args.force, args.dry_run):
        print("Failed to create genesis address secret.", file=sys.stderr)
        sys.exit(1)

    for node in nodes:
        if not grant_secret_access(address_secret_name, project_id, node.get('service_account'), args.dry_run):
            print("Failed to grant access to genesis address secret.", file=sys.stderr)
            sys.exit(1)

    nodes = filter_nodes(nodes)

    for node in nodes:
        if not grant_secret_access(secret_name, project_id, node.get('service_account'), args.dry_run):
            print("Failed to grant access to genesis key secret.", file=sys.stderr)
            sys.exit(1)

    print(f"Successfully generated and stored genesis key as '{secret_name}' and address as '{address_secret_name}'")
