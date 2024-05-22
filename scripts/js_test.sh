echo "The CI is running this script."

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get install solc libsecp256k1-dev protobuf-compiler > /dev/null 2>&1

# Start network early.
pwd
echo "building zilliqa and running it as a detached process"
cargo build --all-targets
ls ./target
RUST_LOG=zilliqa=warn,zilliqa=info ./target/debug/zilliqa 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c config-single-node.toml > /tmp/zil_log_out.txt 2>&1 &

cd evm_scilla_js_tests

# install nvm and switch to desired version
curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash
source ~/.profile

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

echo "Installing nvm"
nvm install 16.0

echo "Using nvm 16"
nvm use 16.0
node --version

echo "Installing tests"

# Install tests
npm install > /dev/null 2>&1

# Need to fund scilla addresses which are distinct from zilliqa, or they will fail due to out of funds
echo "Funding tests"
npx hardhat run scripts/FundAccountsFromEth.ts

echo "Running tests"

# Run tests
# TODO: Remove these files to run all tests.
npx hardhat test ./test/scilla/HelloWorld.ts ./test/GasEstimationCreate.ts

retVal=$?
pkill -INT zilliqa
if [ $retVal -ne 0 ]; then
    cat /tmp/zil_log_out.txt
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
