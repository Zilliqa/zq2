#!/bin/bash

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --accounts-dir)
      ACCOUNTS_DIR="$2"
      shift 2
      ;;
    --log-dir)
      LOG_DIR="$2"
      shift 2
      ;;
    --rpc-endpoint)
      RPC_ENDPOINT="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "$ACCOUNTS_DIR" ] || [ -z "$LOG_DIR" ] || [ -z "$RPC_ENDPOINT" ]; then
  echo "Missing required parameters"
  echo "Usage: $0 --accounts-dir <dir> --log-dir <dir> --rpc-endpoint <endpoint>"
  exit 1
fi

mkdir -p "$LOG_DIR"

cat > "$LOG_DIR/run_load_test.js" << 'EOF'
const { ethers } = require("ethers");
const fs = require('fs');

const nodeUrl = (process.env.RPC_ENDPOINT || "").split(",");

const BATCH_TXS = 4000;
const SEND_AMOUNT = "0.001";

const accounts = JSON.parse(fs.readFileSync(process.env.ACCOUNTS_JSON || "$ACCOUNTS_DIR/accounts.json"));
const account = accounts[0];

async function main() {
    const provider = new ethers.JsonRpcProvider(nodeUrl);
    const wallet = new ethers.Wallet(account.private_key, provider);
    const baseNonce = await provider.getTransactionCount(wallet.address, "latest");
    const txPromises = [];
    console.log(`Using endpoint: ${nodeUrl}`);
    for (let i = 0; i < BATCH_TXS; i++) {
        const tx = {
            to: wallet.address,
            value: ethers.parseEther(SEND_AMOUNT),
            gasLimit: 21000,
            nonce: baseNonce + i
        };
        txPromises.push(
            wallet.sendTransaction(tx)
                .then(txResp => {
                    if ((i+1) % 100 === 0) console.log(`Tx \u001b[32m${i+1}\u001b[0m: ${txResp.hash}`);
                })
                .catch(err => {
                    console.error(`Tx ${i+1} failed: ${err.message}`);
                })
        );
    }
    await Promise.all(txPromises);
    console.log(`Finished sending ${BATCH_TXS} transactions`);
}

main().catch(console.error);
EOF

npm install ethers@6.11.1
ACCOUNTS_JSON="$ACCOUNTS_DIR/accounts.json" RPC_ENDPOINTS="$RPC_ENDPOINT" node "$LOG_DIR/run_load_test.js" 