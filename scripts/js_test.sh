echo "The CI is running this script."
ls
cd evm_js_tests
git pull
ls

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
echo "lets go"
pwd
ls

npm install
echo $PATH

#sudo apt-get update \
#    && apt-get install -y software-properties-common \
#    && add-apt-repository ppa:avsm/ppa -y \
#    && apt-get update && apt-get install -y --no-install-recommends \
#    git \
#    curl \
#    wget \
#    cmake \
#    build-essential \
#    m4 \
#    ocaml \
#    opam \
#    pkg-config \
#    zlib1g-dev \
#    libgmp-dev \
#    libffi-dev \
#    libssl-dev \
#    libsecp256k1-dev \
#    libboost-system-dev \
#    libboost-test-dev \
#    libboost-dev \
#    libpcre3-dev \
#    && rm -rf /var/lib/apt/lists/*
#
#export OCAML_VERSION=4.11.2
#
## CMake gets installed here
#export PATH="/root/.local/bin:${PATH}"
#
#wget https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh
#mkdir -p "${HOME}"/.local
#bash ./cmake-3.19.3-Linux-x86_64.sh --skip-license --prefix="${HOME}"/.local/
#
#RUN bash scripts/install_cmake_ubuntu.sh \
#    && make opamdep-ci \
#    && echo '. ~/.opam/opam-init/init.sh > /dev/null 2> /dev/null || true ' >> ~/.bashrc \
#    && eval $(opam env) && \
#    make
#
##sudo touch /bin/scilla-fmt
##sudo chmod 755 /bin/scilla-fmt
npx hardhat test --network zq2
