#!/bin/bash
echo "CI runs this script."

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get install solc libsecp256k1-dev protobuf-compiler > /dev/null 2>&1

# Start ZQ2 early
pwd
echo "Build and run ZQ2"
cargo build -p zilliqa
RUST_LOG=zilliqa=info,jsonrpsee=trace ./target/debug/zilliqa 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c bundler_tests/config-bundler-spec-tests.toml > /tmp/zil_log_bundler.txt 2>&1 &
echo "Recovering disk space"
cargo clean

# Install NVM
curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash
source ~/.profile

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

echo "Installing nvm"
nvm install 22.12

echo "Using node version 22.12"
nvm use 22.12
node --version
npm install pnpm

cd bundler_tests/

# Pre install contracts
echo "Install Entrypoint v0.8"
npm install @account-abstraction/contracts
cast publish --rpc-url http://localhost:4200 0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222
cast send --rpc-url http://localhost:4200 --private-key 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 0x4e59b44847b379578588920cA78FbF26c0B4956C   "$(node -e "const {bytecode} = require('@account-abstraction/contracts/artifacts/EntryPoint.json'); console.log('0x0a59dbff790c23c976a548690c27297883cc66b4c67024f9117b0238995e35e9' + bytecode.slice(2))")"

# Install Bundler
echo "Install Alto-Bundler"
npm install @pimlico/alto
npx alto \
    -r http://localhost:4200 \
    --port 3000 \
    -e 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 \
    -x 0x65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 \
    -u 0x65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 \
    --enable-debug-endpoints true

# Run spec tests
git clone --depth 1 https://github.com/eth-infinitism/bundler-spec-tests.git --branch version-0.8-addrs
cd bundler-spec-tests/
pdm install && pdm run update-deps

# Run spec tests
pdm test \
    --url http://localhost:3000 \
    --entry-point 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 \
    --ethereum-node http://localhost:4200 \
    tests/single/rpc/

exit $?
