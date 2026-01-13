#!/bin/bash

# Define a cleanup function
cleanup() {
    echo "Container stopped, killing processes..."
    kill -TERM "$child_pid" "$scilla_pid"
    wait "$child_pid"
}

# Trap the SIGTERM signal
trap cleanup SIGTERM

# Start Scilla server
/scilla/0/bin/scilla-server-http --port=$1 &
scilla_pid=$!

# Confirm Scilla Server is responding at specified port
sleep 2
RETRY_COUNT=0
RETRIES=5
while [ $RETRY_COUNT -lt $RETRIES ]; do
  if curl -s -H 'Content-Type: application/json' -X POST -d '{ "id": "1", "jsonrpc": "2.0", "method": "version", "params": [] }' http://localhost:$1/run | grep -q "scilla_version"; then
    echo "Scilla server started successfully on port $1"
    break
  fi
  RETRY_COUNT=$((RETRY_COUNT+1))
  if [ $RETRY_COUNT -eq $RETRIES ]; then
    echo "Error: Cannot connect to Scilla server at localhost:$1"
    exit 1
  fi
  echo "Waiting for Scilla server to respond (attempt $RETRY_COUNT)..."
  sleep 2
done

shift

# Start Zilliqa
/zilliqa $@ &
child_pid=$!

wait "$child_pid"
