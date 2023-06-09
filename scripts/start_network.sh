#set -e
echo "The CI is running this script."
ls
cd evm_js_tests
git pull
ls

# Start network early....
cd ../zilliqa
cargo build --all-targets > /dev/null
pwd
#find / -name zilliqa
#find ../ -type f
#find ../ -name zilliqa
../target/debug/zilliqa 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 > out.txt &
../target/debug/zilliqa 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e --no-jsonrpc > out1.txt &
../target/debug/zilliqa 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364 --no-jsonrpc > out2.txt &
../target/debug/zilliqa db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a --no-jsonrpc > out3.txt &
sleep 10;
curl -X POST http://localhost:4201 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":"1","method":"eth_getBalance", "params": ["0x6f1ec4ca9228ea36a14f0e4e336e71a1851d679b", "latest"]}'
cd ../

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

cd -

find ./ -name zilliqa
echo "should be here, right"
ps -e | grep zil
ls ./target/debug/zilliqa

cd -
echo "lets go"
pwd
ls
cd evm_js_tests

sudo add-apt-repository ppa:ethereum/ethereum > /dev/null
sudo apt-get update > /dev/null
sudo apt-get install solc libsecp256k1-dev > /dev/null

npm install > /dev/null
echo $PATH

echo "now we run the test..."

curl -X POST http://localhost:4201 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":"1","method":"eth_getBalance", "params": ["0x6f1ec4ca9228ea36a14f0e4e336e71a1851d679b", "latest"]}'
ps -e | grep zil


#npm install
DEBUG=true MOCHA_TIMEOUT=400000 npx hardhat test --grep "should return a send raw transaction" --bail --network zq2

retVal=$?

pkill -INT zilliqa
cat npx.out
if [ $retVal -ne 0 ]; then
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
