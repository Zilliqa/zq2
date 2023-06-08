#set -e
echo "The CI is running this script."
ls
cd evm_js_tests
git pull
ls

# Start network early....
cd ../zilliqa
#cargo run
#cargo run -- 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 > out.txt &
#cargo run -- 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e --no-jsonrpc > out1.txt &
#cargo run -- 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364 --no-jsonrpc > out2.txt &
#cargo run -- db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a --no-jsonrpc > out3.txt &
#sleep 30;
cd ../

# Install dependencies silently on the CI server

# install dependencies
sudo apt update
sudo apt -y install gpg python3 lsb-core curl dirmngr apt-transport-https lsb-release ca-certificates
## Adding the NodeSource signing key to your keyring...
curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | gpg --dearmor | tee /usr/share/keyrings/nodesource.gpg >/dev/null

## Creating apt sources list file for the NodeSource Node.js 14.x repo...

echo 'deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_14.x jammy main' > /etc/apt/sources.list.d/nodesource.list
echo 'deb-src [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_14.x jammy main' >> /etc/apt/sources.list.d/nodesource.list

sudo apt update
sudo apt -y install nodejs
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

npm install
echo $PATH
