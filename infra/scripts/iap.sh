#!/bin/bash

# --- Configuration: Replace with your values ---
PROJECT_ID="prj-d-zq2-devnet-c83bkpsd"
ZONE="asia-southeast1-c"                 # e.g., "us-central1-a"
INSTANCE_NAME="zq2-devnet-api-ase1-2"
INSTANCE_PORT="4202"                       # The port your service is listening on inside the VM
LOCAL_PORT="9999"                          # A free port on your local machine to use for the tunnel
ENDPOINT_PATH="/"             # The specific endpoint path you want to curl
# --- End Configuration ---

# 1. Start the IAP tunnel in the background
echo "Starting IAP tunnel from localhost:${LOCAL_PORT} to ${INSTANCE_NAME}:${INSTANCE_PORT}..."
gcloud compute start-iap-tunnel \
    "${INSTANCE_NAME}" "${INSTANCE_PORT}" \
    --project="${PROJECT_ID}" \
    --zone="${ZONE}" \
    --local-host-port="localhost:${LOCAL_PORT}" &

# Capture the Process ID (PID) of the backgrounded tunnel command
TUNNEL_PID=$!

echo "IAP tunnel PID:${TUNNEL_PID}..."

# 2. Set up a trap to ensure the tunnel is killed when the script exits
# This is crucial for cleanup, even if the script is interrupted (Ctrl+C).
trap "echo -e '\nKilling tunnel PID ${TUNNEL_PID}'; kill ${TUNNEL_PID}" EXIT

# 3. Poll the local port to see when the tunnel is ready
echo "Waiting for tunnel to be ready..."
MAX_RETRIES=20 # 20 retries * 0.5s sleep = 10 second timeout
RETRY_COUNT=0
# Loop until the port is open or we time out
until nc -zvw1 localhost "${LOCAL_PORT}" &> /dev/null
do
  if [ ${RETRY_COUNT} -ge ${MAX_RETRIES} ]; then
    echo "Error: Timed out waiting for IAP tunnel to start on port ${LOCAL_PORT}."
    # The trap will kill the background process upon exit
    exit 1
  fi
  RETRY_COUNT=$((RETRY_COUNT+1))
  sleep 0.5
  echo -n "." # Progress indicator
done

echo -e "\nTunnel is ready!"

# 4. Run your curl command against the local port
echo "Curling local endpoint: http://localhost:${LOCAL_PORT}${ENDPOINT_PATH}"
curl -X POST -H "Content-Type:application/json" -H "accept:application/json,*/*;q=0.5" --data '{"jsonrpc":"2.0", "id":"1", "method":"txpool_status","params": []}' http://localhost:${LOCAL_PORT}${ENDPOINT_PATH}

CURL_EXIT_CODE=$?

# The 'trap' command will automatically kill the tunnel process when the script exits.
echo -e "\nScript finished. Tunnel will be closed."

# Exit with the same code as curl
exit $CURL_EXIT_CODE
