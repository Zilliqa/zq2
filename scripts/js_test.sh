echo "The CI is running this script."

# Start network early.
pwd
cargo build --all-targets > /dev/null 2>&1
RUST_LOG=zilliqa=trace ./target/debug/z2 internal run > /tmp/zil_log_out.txt 2>&1 &
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

echo "Installing nvm"
nvm install 16.0

echo "Using nvm"
nvm use 16.0
node --version

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get install solc libsecp256k1-dev ansi2txt > /dev/null 2>&1

echo "install ansi dedup"
git clone https://github.com/drakkan/ansi2txt.git
cd ansi2txt
cargo build --release
cp target/release/ansi2txt /usr/local/bin/

echo "Installing tests"

# Install tests
npm install > /dev/null 2>&1

echo "Running tests"

# Run tests
npx hardhat test

retVal=$?

pkill -INT zilliqa
if [ $retVal -ne 0 ]; then
    cat /tmp/zil_log_out.txt | ansi2txt
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
