echo "The CI is running this script."

# Start network early.
pwd
cargo build --all-targets > /dev/null 2>&1
./target/debug/z2 internal run > /tmp/zil_log_out.txt &
sleep 10;

# Pull submodule
cd evm_js_tests
git pull

# install nvm and switch to desired
curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash
source ~/.profile

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

nvm install 16.0
nvm use 16.0
node --version

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get install solc libsecp256k1-dev > /dev/null 2>&1

# Install tests
npm install > /dev/null 2>&1

# Run tests
npx hardhat test

retVal=$?

pkill -INT zilliqa
cat npx.out
if [ $retVal -ne 0 ]; then
    cat /tmp/zil_log_out.txt
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
