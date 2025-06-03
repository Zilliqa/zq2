#!/usr/bin/env python3

import argparse
from google.cloud import secretmanager
from google.api_core import exceptions

def delete_secrets_with_label(project_id: str, label_key: str, label_value: str):
    """
    Delete all secrets in a GCP project that have a specific label.
    
    Args:
        project_id (str): The GCP project ID
        label_key (str): The label key to match
        label_value (str): The label value to match
    """
    # Initialize the Secret Manager client
    client = secretmanager.SecretManagerServiceClient()
    
    # Construct the parent project path
    parent = f"projects/{project_id}"
    
    try:
        # List all secrets in the project
        secrets = client.list_secrets(request={"parent": parent})
        
        deleted_count = 0
        for secret in secrets:
            # Check if the secret has the specified label
            if secret.labels.get(label_key) == label_value:
                try:
                    # Delete the secret
                    secret_name = secret.name
                    client.delete_secret(request={"name": secret_name})
                    print(f"Deleted secret: {secret_name}")
                    deleted_count += 1
                except exceptions.NotFound:
                    print(f"Secret {secret_name} not found")
                except exceptions.PermissionDenied:
                    print(f"Permission denied to delete secret: {secret_name}")
                except Exception as e:
                    print(f"Error deleting secret {secret_name}: {str(e)}")
        
        print(f"\nTotal secrets deleted: {deleted_count}")
        
    except exceptions.PermissionDenied:
        print(f"Permission denied to list secrets in project {project_id}")
    except Exception as e:
        print(f"Error listing secrets: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Delete GCP secrets with specific labels")
    parser.add_argument("--project-id", required=True, help="GCP project ID")
    parser.add_argument("--label-key", default="zq2-network", help="Label key to match")
    parser.add_argument("--label-value", required=True, help="Label value to match")
    
    args = parser.parse_args()
    
    print(f"Deleting secrets in project {args.project_id} with label {args.label_key}={args.label_value}")
    delete_secrets_with_label(args.project_id, args.label_key, args.label_value)

if __name__ == "__main__":
    main() 