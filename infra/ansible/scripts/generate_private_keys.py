#!/usr/bin/env python3

import argparse
import asyncio
import subprocess
import sys
import yaml
import json
from typing import List, Dict, Any, Optional
import os
import time
import tempfile
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from tqdm import tqdm
from secret_key import SecretKey

# --- Argument Parsing ---
def parse_args():
    parser = argparse.ArgumentParser(description='Generate private keys for Zilliqa 2 nodes (GCP)')
    parser.add_argument('config_file', help='Path to network YAML configuration')
    parser.add_argument('--project-id', required=True, help='GCP project ID')
    parser.add_argument('--select', action='store_true', help='Interactive node selection')
    parser.add_argument('--force', action='store_true', help='Overwrite existing keys')
    parser.add_argument('--dry-run', action='store_true', help='Simulate actions without making any changes')
    parser.add_argument('--kms', action='store_true', help='Enable KMS encryption for keys')
    return parser.parse_args()

# --- Load Network Configuration ---
def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config

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
    """Exclude nodes with role == 'apps' from key generation."""
    return [n for n in nodes if n.get('labels', {}).get('role') != 'apps']

def select_nodes_interactively(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("Select nodes to generate keys for (comma-separated indices, or 'all'):")
    for idx, node in enumerate(nodes):
        print(f"[{idx}] {node['name']} (role={node.get('labels', {}).get('role', 'unknown')}, zone={node['zone']})")
    selection = input("Enter selection: ").strip()
    if selection.lower() == 'all':
        return nodes
    try:
        indices = [int(i) for i in selection.split(',') if i.strip().isdigit()]
        return [nodes[i] for i in indices if 0 <= i < len(nodes)]
    except Exception as e:
        print(f"Invalid selection: {e}", file=sys.stderr)
        sys.exit(1)

CONCURRENCY_LIMIT = 50

def get_secret_name(node: dict, kms_enabled: bool) -> str:
    if kms_enabled:
        return f"{node['name']}-enckey"
    else:
        return f"{node['name']}-pk"

def create_secret_in_gcp(secret_name: str, value: str, project_id: str, labels: dict, force: bool = False, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"[DRY-RUN] Would create secret '{secret_name}' in project '{project_id}' with labels {labels} (force={force}) and value (hidden)")
        return True
    # Check if secret exists
    check_cmd = ["gcloud", "secrets", "describe", secret_name, "--project", project_id]
    result = subprocess.run(check_cmd, capture_output=True, text=True)
    if result.returncode == 0 and not force:
        return True  # Already exists, skip
    if result.returncode == 0 and force:
        # Delete existing secret
        del_cmd = ["gcloud", "secrets", "delete", secret_name, "--project", project_id, "--quiet"]
        subprocess.run(del_cmd, capture_output=True)
    # Create secret
    create_cmd = [
        "gcloud", "secrets", "create", secret_name,
        "--project", project_id,
        "--replication-policy", "automatic"
    ]
    for k, v in labels.items():
        create_cmd.extend(["--labels", f"{k}={v}"])
    create_result = subprocess.run(create_cmd, capture_output=True, text=True)
    if create_result.returncode != 0:
        return False
    
    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as tmp:
        tmp.write(value)
        tmp.flush()
    # Add secret version
    version_cmd = [
        "gcloud", "secrets", "versions", "add", secret_name,
        "--project", project_id,
        "--data-file", os.path.abspath(tmp.name)
    ]
    version_result = subprocess.run(version_cmd, capture_output=True, text=True)
    return version_result.returncode == 0

def grant_secret_access(secret_name: str, project_id: str, service_account: str, dry_run: bool = False) -> bool:
    if not service_account:
        return False
    if dry_run:
        print(f"[DRY-RUN] Would grant roles/secretmanager.secretAccessor on '{secret_name}' to serviceAccount:{service_account} in project '{project_id}'")
        return True
    add_iam_cmd = [
        "gcloud", "secrets", "add-iam-policy-binding", secret_name,
        "--project", project_id,
        "--member", f"serviceAccount:{service_account}",
        "--role", "roles/secretmanager.secretAccessor"
    ]
    result = subprocess.run(add_iam_cmd, capture_output=True, text=True)
    return result.returncode == 0

def get_kms_project_id(project_id: str) -> str:
    # Use the same logic as the provisioning script
    if project_id.startswith("prj-p"):
        return "prj-p-kms-2vduab0g"
    else:
        return "prj-d-kms-tw1xyxbh"

def encrypt_with_kms(plaintext: str, project_id: str, chain_name: str, node_name: str, dry_run: bool = False) -> str:
    if dry_run:
        print(f"[DRY-RUN] Would encrypt key for node '{node_name}' using KMS key in project '{project_id}', keyring 'kms-{chain_name}', key '{node_name}'")
        return "DRYRUN_ENCRYPTED_KEY=="
    kms_project_id = get_kms_project_id(project_id)
    keyring = f"kms-{chain_name}"
    key = node_name
    # Write plaintext to a temp file
    import tempfile, base64
    with tempfile.NamedTemporaryFile(delete=False) as ptf:
        ptf.write(plaintext.encode())
        ptf.flush()
        ciphertext_file = ptf.name + ".enc"
        cmd = [
            "gcloud", "kms", "encrypt",
            f"--project={kms_project_id}",
            "--location=global",
            f"--keyring={keyring}",
            f"--key={key}",
            f"--plaintext-file={ptf.name}",
            f"--ciphertext-file={ciphertext_file}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"KMS encryption failed: {result.stderr}")
        # Read ciphertext and base64 encode
        with open(ciphertext_file, 'rb') as cf:
            ciphertext = cf.read()
        os.remove(ptf.name)
        os.remove(ciphertext_file)
        return base64.b64encode(ciphertext).decode()

async def process_node(node: dict, kms_enabled: bool, project_id: str, chain_name: str, force: bool, pbar=None, dry_run: bool = False) -> dict:
    try:
        # Generate key
        if dry_run:
            print(f"[DRY-RUN] Would generate private key for node '{node['name']}'")
            key_hex = "DRYRUN_PRIVATE_KEY"
        else:
            secret_key = SecretKey.new()
            key_hex = secret_key.to_hex()
        secret_name = get_secret_name(node, kms_enabled)
        labels = {
            "role": node.get('labels', {}).get('role', ''),
            "zq2-network": chain_name,
            "node-name": node['name'],
            "is-private-key": "true"
        }
        # Encrypt with KMS if enabled
        if kms_enabled:
            try:
                key_hex = encrypt_with_kms(key_hex, project_id, chain_name, node['name'], dry_run=dry_run)
            except Exception as e:
                if pbar:
                    pbar.update(1)
                return {"node": node['name'], "error": f"KMS encryption failed: {e}"}
        # Store secret
        ok = create_secret_in_gcp(secret_name, key_hex, project_id, labels, force=force, dry_run=dry_run)
        if not ok:
            return {"node": node['name'], "error": "Failed to create secret"}
        # Grant access
        granted = grant_secret_access(secret_name, project_id, node.get('service_account'), dry_run=dry_run)
        if not granted:
            return {"node": node['name'], "error": "Failed to grant IAM access"}
        if pbar:
            pbar.update(1)
        return {"node": node['name'], "status": "ok"}
    except Exception as e:
        if pbar:
            pbar.update(1)
        return {"node": node['name'], "error": str(e)}

async def main_async(nodes, config, force, dry_run, kms_enabled):
    project_id = nodes[0]['project_id'] if nodes else None
    chain_name = config.get('name')
    results = []
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    loop = asyncio.get_event_loop()
    with tqdm(total=len(nodes), desc="Generating keys & storing secrets" if not dry_run else "Simulating key generation & secret storage") as pbar:
        async def sem_task(node):
            async with sem:
                return await process_node(node, kms_enabled, project_id, chain_name, force, pbar, dry_run=dry_run)
        tasks = [sem_task(node) for node in nodes]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
    return results

if __name__ == "__main__":
    args = parse_args()
    config = load_config(args.config_file)
    chain_name = config.get('name')
    if not chain_name:
        print("Could not determine chain/network name from config.", file=sys.stderr)
        sys.exit(1)
    nodes = discover_gcp_nodes(chain_name, args.project_id)
    nodes = filter_nodes(nodes)
    if not nodes:
        print("No eligible nodes found for key generation.", file=sys.stderr)
        sys.exit(1)
    if args.select:
        nodes = select_nodes_interactively(nodes)
    print(f"Selected {len(nodes)} nodes for key generation.")
    # Run async key generation and secret storage (or dry-run)
    results = asyncio.run(main_async(nodes, config, args.force, args.dry_run, args.kms))
    # Report errors
    errors = [r for r in results if r.get('error')]
    if errors:
        print("\nSome errors occurred:")
        for err in errors:
            print(err)
    else:
        print("\nAll keys generated and secrets stored successfully." if not args.dry_run else "\nDry-run completed. No changes were made.") 