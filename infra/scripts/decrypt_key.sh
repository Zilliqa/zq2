#!/bin/bash

# Check if node name argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <node_name>"
    echo "Example: $0 zq2-infratest-api-ase1-2-30a5"
    exit 1
fi

# Parse node name argument
NODE_NAME="$1"

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
echo "Decrypting with the following parameters:"
echo "Node Name: $NODE_NAME"
echo "Extracted Chain Name: $CHAIN_NAME"
echo "Determined Project ID: $PROJECT_ID"
echo "KMS Project ID: $KMS_PROJECT_ID"
echo "Keyring: $KEYRING"
echo

# Perform the decryption
echo "Executing decryption command..."
DECRYPTED_VALUE=$(gcloud secrets versions access latest --project="$PROJECT_ID" --secret="${NODE_NAME}-enckey" | base64 -d | gcloud kms decrypt --ciphertext-file=- --plaintext-file=- --key="$NODE_NAME" --keyring="$KEYRING" --location=global --project="$KMS_PROJECT_ID")

# Check if the command succeeded
if [ $? -eq 0 ]; then
    echo "Decryption successful!"
    echo "Decrypted value:"
    echo "$DECRYPTED_VALUE"
else
    echo "Error: Decryption failed"
    exit 1
fi