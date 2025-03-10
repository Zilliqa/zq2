#!/bin/bash

trap 'kill $(jobs -p) 2>/dev/null' EXIT

# Start Scilla server
/scilla/0/bin/scilla-server-http --port=$1 &

shift

# Start Zilliqa
/zilliqa $@
