#!/usr/bin/env python3

import argparse
import sys
import base64
import yaml
import json
import os
import subprocess
import tempfile
from typing import List, Dict, Any
from convert_key import convert_key_rust

# --- Argument Parsing ---
def parse_args():
    parser = argparse.ArgumentParser(description='Aggregate node/genesis keys and produce a config JSON using convert_key.py')
    parser.add_argument('config_file', help='Path to network YAML configuration')
    parser.add_argument('--project-id', required=True, help='GCP project ID')
    parser.add_argument('--output', help='Output JSON file')
    parser.add_argument('--kms', action='store_true', help='Keys are KMS-encrypted')
    parser.add_argument('--dry-run', action='store_true', help='Simulate actions without making any changes')
    return parser.parse_args()

# --- Load Network Configuration ---
def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

# --- GCP Node Discovery ---
def discover_gcp_nodes(chain_name: str) -> List[Dict[str, Any]]:
    cmd = [
        'gcloud', 'compute', 'instances', 'list',
        '--filter', f'labels.zq2-network={chain_name}',
        '--format', 'json'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running gcloud: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    instances = json.loads(result.stdout)
    nodes = []
    for inst in instances:
        node = {
            'project_id': inst['zone'].split('/')[-3],
            'zone': inst['zone'].split('/')[-1],
            'name': inst['name'],
            'status': inst['status'],
            'labels': inst.get('labels', {}),
            'service_account': inst.get('serviceAccounts', [{}])[0].get('email'),
        }
        nodes.append(node)
    return nodes

def filter_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Exclude nodes with role == 'apps' from key generation."""
    return [n for n in nodes if n.get('labels', {}).get('role') != 'apps']

def filter_running_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Exclude nodes not in state 'RUNNING'."""
    return [n for n in nodes if n.get('status') == 'RUNNING']

def get_secret_name(node_name: str, kms_enabled: bool) -> str:
    return f"{node_name}-enckey" if kms_enabled else f"{node_name}-pk"

def get_genesis_secret_name(chain_name: str, kms_enabled: bool) -> str:
    return f"{chain_name}-genesis-enckey" if kms_enabled else f"{chain_name}-genesis"

def get_kms_project_id(project_id: str) -> str:
    if project_id.startswith("prj-p"):
        return "prj-p-kms-2vduab0g"
    else:
        return "prj-d-kms-tw1xyxbh"

def fetch_secret(secret_name: str, project_id: str) -> str:
    cmd = [
        "gcloud", "secrets", "versions", "access", "latest",
        "--secret", secret_name,
        "--project", project_id
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to fetch secret {secret_name}: {result.stderr}")
    return result.stdout.strip()

def decrypt_with_kms(ciphertext_b64: str, project_id: str, chain_name: str, key_name: str) -> str:
    import base64
    kms_project_id = get_kms_project_id(project_id)
    keyring = f"kms-{chain_name}"
    location = "global"
    # Write ciphertext to a temp file
    with tempfile.NamedTemporaryFile(delete=False) as cf:
        cf.write(base64.b64decode(ciphertext_b64))
        cf.flush()
        plaintext_file = cf.name + ".plain"
        cmd = [
            "gcloud", "kms", "decrypt",
            f"--project={kms_project_id}",
            f"--location={location}",
            f"--keyring={keyring}",
            f"--key={key_name}",
            f"--ciphertext-file={cf.name}",
            f"--plaintext-file={plaintext_file}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            os.remove(cf.name)
            raise RuntimeError(f"KMS decryption failed: {result.stderr}")
        with open(plaintext_file, 'r') as pf:
            plaintext = pf.read().strip()
        os.remove(cf.name)
        os.remove(plaintext_file)
        return plaintext

def add_peer_id_label(node_name: str, project_id: str, zone: str, peer_id: str, dry_run: bool = False) -> bool:
    """Add peer ID label to GCP instance."""
    if dry_run:
        print(f"[DRY-RUN] Would add label peer_id={peer_id.lower()} to instance {node_name}")
        return True
    
    cmd = [
        "gcloud", "compute", "instances", "add-labels",
        "--project", project_id,
        "--zone", zone,
        node_name,
        f"--labels=peer-id={peer_id.lower()}"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error adding peer ID label to {node_name}: {result.stderr}", file=sys.stderr)
        return False
    
    print(f"Successfully added peer ID label to {node_name}")
    return True

def create_secret_in_gcp(secret_name: str, value: str, project_id: str, chain_name: str, force: bool = False, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"[DRY-RUN] Would create secret '{secret_name}' in project '{project_id}' (force={force}) and value (hidden)")
        return True
    # Check if secret exists
    check_cmd = ["gcloud", "secrets", "describe", secret_name, "--project", project_id]
    result = subprocess.run(check_cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        if not force:
            print(f"Secret '{secret_name}' already exists. Use --force to overwrite.")
            return True
        # Delete existing secret if force is True
        del_cmd = ["gcloud", "secrets", "delete", secret_name, "--project", project_id, "--quiet"]
        subprocess.run(del_cmd, capture_output=True)
    
    # Create secret with labels
    create_cmd = [
        "gcloud", "secrets", "create", secret_name,
        "--project", project_id,
        "--replication-policy", "automatic",
        "--labels", f"role=keys-config,zq2-network={chain_name}"
    ]
    
    create_result = subprocess.run(create_cmd, capture_output=True, text=True)
    if create_result.returncode != 0:
        print(f"Error creating secret: {create_result.stderr}", file=sys.stderr)
        return False
    
    # Add secret version
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

if __name__ == "__main__":
    args = parse_args()
    config = load_config(args.config_file)
    chain_name = config.get('name')
    chain_id = config.get('eth_chain_id')
    if not chain_name or not chain_id:
        print("Could not determine chain/network name or eth_chain_id from config.", file=sys.stderr)
        sys.exit(1)
    project_id = args.project_id
    output = {}

    # Discover nodes
    nodes = discover_gcp_nodes(chain_name)
    running_nodes = filter_running_nodes(nodes)
    running_nodes = filter_nodes(running_nodes)
    for node in running_nodes:
        node_name = node['name']
        secret_name = get_secret_name(node_name, args.kms)
        try:
            secret_value = fetch_secret(secret_name, project_id)
            if args.kms:
                secret_value = decrypt_with_kms(secret_value, project_id, chain_name, node_name)
            output[node_name] = convert_key_rust(secret_value, chain_id)
            print(f"Successfully processed node {node_name}")
            peer_id = output[node_name]['peer_id']
            
            # Add peer ID label to instance
            if not add_peer_id_label(node_name, project_id, node['zone'], peer_id, args.dry_run):
                print(f"Warning: Failed to add peer ID label to {node_name}", file=sys.stderr)
            
        except Exception as e:
            print(f"Error processing node {node_name}: {e}", file=sys.stderr)
            output[node_name] = {"error": str(e)}

    # Genesis key
    genesis_secret_name = get_genesis_secret_name(chain_name, args.kms)
    try:
        genesis_value = fetch_secret(genesis_secret_name, project_id)
        if args.kms:
            genesis_value = decrypt_with_kms(genesis_value, project_id, chain_name, f"{chain_name}-genesis")
        output["genesis-key"] = convert_key_rust(genesis_value, chain_id)
    except Exception as e:
        print(f"Error processing genesis key: {e}", file=sys.stderr)
        output["genesis-key"] = {"error": str(e)}

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"Wrote keys config to {args.output}")

    key_hex = base64.b64encode(json.dumps(output).encode()).decode()
    secret_name = f"{chain_name}-keys-config"
    
    # Store secret
    if not create_secret_in_gcp(secret_name, key_hex, project_id, chain_name, True, dry_run=args.dry_run):
        print("Failed to create secret.", file=sys.stderr)
        sys.exit(1)

    for node in nodes:
        # Grant access
        if not grant_secret_access(secret_name, args.project_id, node.get('service_account'), dry_run=args.dry_run):
            print("Failed to grant access to secret.", file=sys.stderr)
            sys.exit(1)

    print(f"Successfully generated and stored keys config as '{secret_name}'")
