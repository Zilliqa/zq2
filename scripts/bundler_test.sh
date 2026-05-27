#!/bin/bash
echo "CI runs this script."

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get install solc libsecp256k1-dev protobuf-compiler > /dev/null 2>&1

# Start ZQ2 early
pwd
echo "Build and run ZQ2"
cargo build -p zilliqa
RUST_LOG=zilliqa=warn,jsonrpsee=trace ./target/debug/zilliqa 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c bundler_tests/config-bundler-spec-tests.toml > /tmp/zil_log_bundler.txt 2>&1 &
echo "Recovering disk space"
cargo clean

# wait till ZQ2 runs
timeout 60 bash -c 'until curl -o /dev/null -sf http://localhost:4201/health; do sleep 1; done'

# download rundler
echo "Download Rundler v0.11.0"
git clone --depth 1 https://github.com/alchemyplatform/rundler.git --branch v0.11.0

# patch test scripts
cd rundler/
sed -i 's/--network localhost/--network proxy --reset/' test/spec-tests/local/launcher.sh
sed -i 's|tests/single|tests/single/rpc|' test/spec-tests/local/run-spec-tests-v0_8.sh
(cd test/spec-tests/v0_8/bundler-spec-tests && pdm install && pdm run update-deps)
bash test/spec-tests/local/run-spec-tests-v0_8.sh

# cleanup
retVal=$?
pkill zilliqa
if [ $retVal -ne 0 ]; then
    cat /tmp/zil_log_bundler.txt
    exit 1
fi

echo "Success with bundler-spec-test test"
exit 0
