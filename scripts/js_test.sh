echo "The CI is running this script."
ls
cd evm_js_tests

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
ls ./target/debug/zilliqa

cd -
pwd

npx hardhat test --network zq2
