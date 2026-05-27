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

# install nvm and switch to desired version
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
npm install pnpm

# link solc directly to skip download
mkdir -p $HOME/.solcx/
ln -s $(which solc) $HOME/.solcx/solc-v0.8.28

# install tests and deps
git clone --depth 1 https://github.com/alchemyplatform/bundler-spec-tests.git --branch releases/v0.8
sed -i 's|git@github.com:|https://github.com/|' bundler-spec-tests/.gitmodules
(cd bundler-spec-tests/ && pdm install && pdm run update-deps)

# install entrypoint countract
timeout 60 bash -c 'until curl -o /dev/null -sf http://localhost:4201/health; do sleep 1; done'
(cd bundler-spec-tests/@account-abstraction && yarn install && yarn deploy --network proxy --reset)

# run the test
timeout 60 bash -c 'until curl -o /dev/null -sf http://localhost:3545/health; do sleep 1; done'
(cd bundler-spec-tests/ && pdm run pytest tests/single/rpc --tb=short -rA -W ignore::DeprecationWarning --url http://localhost:3545/rpc --entry-point 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 --ethereum-node http://localhost:8545/)

# cleanup
retVal=$?
pkill zilliqa
if [ $retVal -ne 0 ]; then
    cat /tmp/zil_log_bundler.txt
    exit 1
fi

echo "Success with bundler-spec-test test"
exit 0
