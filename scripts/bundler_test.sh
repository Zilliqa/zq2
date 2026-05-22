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

# Install NVM
curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash
source ~/.profile

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

echo "Installing nvm"
nvm install 22.22

echo "Using node version 22.22"
nvm use 22.22
node --version

# link solc directly to skip download
mkdir -p $HOME/.solcx/
ln -s $(which solc) $HOME/.solcx/solc-v0.8.28

# Update bundler-spec-tests, hacking the remote origin url as SSH does not work in CI
git clone --depth 1 https://github.com/eth-infinitism/bundler-spec-tests.git --branch version-0.8-addrs
pushd bundler-spec-tests/
git config --file=.gitmodules submodule.@rip7560.url https://github.com/eth-infinitism/rip7560_contracts.git
pdm install && pdm run update-deps-remote
popd

# wait till ZQ2 runs
timeout 60 bash -c 'until curl -o /dev/null -sf http://localhost:4201/health; do sleep 1; done'

# Pre install contracts
echo "Install Entrypoint v0.8"
npm install hardhat@3.5.0
pushd bundler-spec-tests/@account-abstraction/
yarn deploy --network proxy
popd

# Install Bundler
echo "Install Alto-Bundler"
npm install @pimlico/alto
npx alto --config bundler_tests/alto-config.json > /tmp/alto_log.txt 2>&1 &
timeout 60 bash -c 'until curl -o /dev/null -sf http://localhost:3000/health; do sleep 1; done'

# Run spec tests
pushd bundler-spec-tests/
pdm test \
    --url http://localhost:3000 \
    --entry-point 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 \
    --ethereum-node http://localhost:4200 \
    tests/single/rpc/
popd

# cleanup
retVal=$?
pkill zilliqa
pkill alto
if [ $retVal -ne 0 ]; then
    cat /tmp/zil_log_bundler.txt
    exit 1
fi

echo "Success with bundler-spec-test test"
exit 0
