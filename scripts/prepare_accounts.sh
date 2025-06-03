#!/bin/bash

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --num-accounts)
      NUM_ACCOUNTS="$2"
      shift 2
      ;;
    --faucet-pk)
      FAUCET_PK="$2"
      shift 2
      ;;
    --rpc-endpoint)
      RPC_ENDPOINT="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown parameter: $1"
      exit 1
      ;;
  esac
done

# Validate required parameters
if [ -z "$NUM_ACCOUNTS" ] || [ -z "$FAUCET_PK" ] || [ -z "$RPC_ENDPOINT" ] || [ -z "$OUTPUT_DIR" ]; then
  echo "Missing required parameters"
  echo "Usage: $0 --num-accounts <number> --faucet-pk <private_key> --rpc-endpoint <url> --output-dir <directory>"
  exit 1
fi

# Set default number of accounts to 30 if not provided
NUM_ACCOUNTS=${NUM_ACCOUNTS:-30}

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create Python script for account generation and funding
cat > "$OUTPUT_DIR/generate_accounts.py" << 'EOF'
import json
import math
import os
import sys
from web3 import Web3
from eth_account import Account
from eth_utils import to_checksum_address
from multiprocessing import Pool, cpu_count, Lock, Value
import time

# Global nonce counter and lock
nonce_counter = None
nonce_lock = None

def init_globals(counter, lock):
    global nonce_counter, nonce_lock
    nonce_counter = counter
    nonce_lock = lock

def get_next_nonce():
    with nonce_lock:
        current = nonce_counter.value
        nonce_counter.value += 1
        return current

def fund_account(args):
    i, account, faucet_address, faucet_key, rpc_endpoint = args
    try:
        # Create new Web3 instance for this process
        w3 = Web3(Web3.HTTPProvider(rpc_endpoint))
        
        # Get next nonce using the global counter
        nonce = get_next_nonce()
        
        # Build transaction
        tx = {
            'nonce': nonce,
            'to': account["address"],
            'value': w3.to_wei(5000, 'ether'),  # 5000 ZIL (5k Zils)
            'gas': 21000,
            'gasPrice': w3.eth.gas_price,
            'chainId': w3.eth.chain_id
        }
        
        # Sign and send transaction
        signed_tx = w3.eth.account.sign_transaction(tx, faucet_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        return {
            'index': i,
            'tx_hash': tx_hash.hex(),
            'account': account["address"],
            'success': True
        }
            
    except Exception as e:
        print(f"Error sending transaction for account {i}: {str(e)}")
        return {
            'index': i,
            'account': account["address"],
            'success': False,
            'error': str(e)
        }

def check_transaction_status(args):
    tx_hash, rpc_endpoint = args
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_endpoint))
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt['status'] == 1
    except Exception as e:
        print(f"Error checking transaction {tx_hash}: {str(e)}")
        return False

def generate_and_fund_accounts(num_accounts, faucet_pk, rpc_endpoint, output_dir):
    # Initialize Web3
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))
    
    # Create faucet account
    faucet = Account.from_key(faucet_pk)
    faucet_address = to_checksum_address(faucet.address)
    
    # Get initial nonce
    initial_nonce = w3.eth.get_transaction_count(faucet_address)
    
    # Generate accounts first
    accounts = []
    for i in range(num_accounts):
        # Generate new account
        account = Account.create()
        account_data = {
            "address": to_checksum_address(account.address),
            "private_key": account.key.hex(),
            "nonce": 0
        }
        accounts.append(account_data)
    
    # Save accounts to file immediately
    with open(os.path.join(output_dir, "accounts.json"), "w") as f:
        json.dump(accounts, f, indent=2)
    
    print(f"Generated {len(accounts)} accounts")
    
    # Initialize global nonce counter and lock
    counter = Value('i', initial_nonce)
    lock = Lock()
    
    # Ensure at least 1 process is used
    num_processes = max(1, min(num_accounts, cpu_count()))
    
    # Prepare arguments for parallel processing
    pool_args = [(i, account, faucet_address, faucet.key, rpc_endpoint) for i, account in enumerate(accounts)]
    
    # Send all funding transactions in parallel
    print(f"Sending funding transactions for {len(accounts)} accounts using {num_processes} processes...")
    with Pool(num_processes, initializer=init_globals, initargs=(counter, lock)) as pool:
        results = pool.map(fund_account, pool_args)
    
    # Filter successful transactions
    successful_txs = [r for r in results if r['success']]
    print(f"Successfully sent {len(successful_txs)} funding transactions")
    
    # Check transaction statuses in parallel
    print("Checking transaction statuses...")
    check_args = [(r['tx_hash'], rpc_endpoint) for r in successful_txs]
    with Pool(num_processes) as pool:
        statuses = pool.map(check_transaction_status, check_args)
    
    # Count successful fundings
    successful_funds = sum(1 for status in statuses if status)
    print(f"Successfully funded {successful_funds} out of {len(accounts)} accounts")
    
    # Report failed transactions
    failed_txs = [r for r in results if not r['success']]
    if failed_txs:
        print("\nFailed transactions:")
        for tx in failed_txs:
            print(f"Account {tx['account']}: {tx.get('error', 'Unknown error')}")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python generate_accounts.py <num_accounts> <faucet_pk> <rpc_endpoint> <output_dir>")
        sys.exit(1)
    
    generate_and_fund_accounts(
        int(sys.argv[1]),
        sys.argv[2],
        sys.argv[3],
        sys.argv[4]
    )
EOF

# Install required Python packages
pip install -r requirements.txt

# Run the account generation script
python "$OUTPUT_DIR/generate_accounts.py" "$NUM_ACCOUNTS" "$FAUCET_PK" "$RPC_ENDPOINT" "$OUTPUT_DIR"

# Make the script executable
chmod +x "$OUTPUT_DIR/generate_accounts.py" 
