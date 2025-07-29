#!/bin/bash

# Check if required arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <node_name> <plaintext_key>"
    echo "Example: $0 zq2-infratest-api-ase1-2-30a5 myPlaintextKeyHere"
    exit 1
fi

# Parse arguments
NODE_NAME="$1"
PLAINTEXT_KEY="$2"

# Extract chain name from the first two blocks of the node name
CHAIN_NAME=$(echo "$NODE_NAME" | cut -d '-' -f 1,2)

# Define project ID dictionary based on chain name
case "$CHAIN_NAME" in
    "zq2-mainnet")
        PROJECT_ID="prj-p-zq2-mainnet-sn5n8wfl"
        ;;
    "zq2-testnet")
        PROJECT_ID="prj-d-zq2-testnet-g13pnaa8"
        ;;
    *)
        PROJECT_ID="prj-d-zq2-devnet-c83bkpsd"
        ;;
esac

# Calculate KMS project ID based on project prefix
if [[ "$PROJECT_ID" == prj-p* ]]; then
    KMS_PROJECT_ID="prj-p-kms-2vduab0g"
elif [[ "$PROJECT_ID" == prj-d* ]]; then
    KMS_PROJECT_ID="prj-d-kms-tw1xyxbh"
else
    echo "Error: Project ID must start with 'prj-p' or 'prj-d'"
    exit 1
fi

# Form the keyring name
KEYRING="kms-${CHAIN_NAME}"

# Print the parameters for verification
echo "Encrypting with the following parameters:"
echo "Node Name: $NODE_NAME"
echo "Extracted Chain Name: $CHAIN_NAME"
echo "Determined Project ID: $PROJECT_ID"
echo "KMS Project ID: $KMS_PROJECT_ID"
echo "Keyring: $KEYRING"
echo

# Perform the encryption
echo "Executing encryption command..."
ENCRYPTED_VALUE=$(echo "$PLAINTEXT_KEY" | gcloud kms encrypt --plaintext-file=- --ciphertext-file=- --key="$NODE_NAME" --keyring="$KEYRING" --location=global --project="$KMS_PROJECT_ID" | base64)

# Check if the command succeeded
if [ $? -eq 0 ]; then
    echo "Encryption successful!"
    echo "Encrypted value:"
    echo "$ENCRYPTED_VALUE"
else
    echo "Error: Encryption failed"
    exit 1
fi