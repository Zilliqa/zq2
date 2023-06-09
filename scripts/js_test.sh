#set -e
echo "The CI is running this script."

# Start network early....
cd zilliqa
cargo build --all-targets > /dev/null
../target/debug/zilliqa 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 > zil_log_out.txt &
../target/debug/zilliqa 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e --no-jsonrpc > zil_log_out1.txt &
../target/debug/zilliqa 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364 --no-jsonrpc > zil_log_out2.txt &
../target/debug/zilliqa db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a --no-jsonrpc > zil_log_out3.txt &
sleep 5;
cd ../

# Pull submodule
cd evm_js_tests
git pull

# install nvm and switch to desired
curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash 
source ~/.profile

echo "now switch... "
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

nvm install 16.0
nvm use 16.0
node --version

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null
sudo apt-get update > /dev/null
sudo apt-get install solc libsecp256k1-dev > /dev/null

# Install tests
npm install > /dev/null

DEBUG=true MOCHA_TIMEOUT=400000 npx hardhat test --grep "should return a send raw transaction" --bail --network zq2

retVal=$?

pkill -INT zilliqa
cat npx.out
if [ $retVal -ne 0 ]; then
    cat zil_log_out.txt
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
