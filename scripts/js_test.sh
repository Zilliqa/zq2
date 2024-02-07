echo "The CI is running this script."

echo "Starting scilla server"
docker run --rm -p 12345-12347:12345-12347 nhutton/scilla_tcp:1.0 /scilla/0/run_scilla_tcp.sh > scilla_log.txt 2>&1 &

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get install solc libsecp256k1-dev netcat > /dev/null 2>&1

# Block here until we know the scilla server has come online (to avoid network breaking when looking for it)
PORT=12345
# Timeout for each netcat attempt in seconds
TIMEOUT=1
# Interval between checks in seconds
INTERVAL=5

while true; do
    # Check if the port is open using netcat
    nc -z 127.0.0.1 $PORT

    # Check exit status of netcat; 0 if success (port is open)
    if [ $? -eq 0 ]; then
        echo "Scilla port $PORT is open!"
        break
    else
        echo "Scilla port $PORT is not open yet. Checking again in $INTERVAL seconds..."
    fi

    # Wait for a bit before checking again
    sleep $INTERVAL
done

# Start network early.
pwd
echo "building zilliqa and running it as a detached process"
cargo build --all-targets
ls ./target
RUST_LOG=zilliqa=warn,zilliqa=info ./target/debug/zilliqa 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c config-example.toml > /tmp/zil_log_out.txt 2>&1 &

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
npx hardhat test ./test/scilla/HelloWorld.ts

retVal=$?
pkill -INT zilliqa
if [ $retVal -ne 0 ]; then
    cat /tmp/zil_log_out.txt
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
