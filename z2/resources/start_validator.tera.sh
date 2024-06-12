#!/bin/bash

ZQ_VERSION="{{ version }}"
ZQ2_IMAGE="zilliqa/zq2:${ZQ_VERSION}"
CHAIN_NAME="{{ chain_name }}"

NODE_PRIVATE_KEY=${1}
CONFIG_FILE=${2:-${CHAIN_NAME}.toml}

help() {
    cat <<EOF

    help:

    ${0}: startup script for a z2 validator node.

    Copy the $0 script and the generated configuration file ${CHAIN_NAME}.toml
    to an Ubuntu 20.04 LTS with docker installed.

    Run: .$0 [NODE_KEY] [CONFIGURATION_FILE]

    Example:

    To start your validator execute:

    chmod +x ${0}

    export NODE_KEY=<YOUR KEY>
    ${0} $NODE_KEY

EOF

exit 1

}

if [[ -z ${NODE_PRIVATE_KEY} ]]; then
    cat <<-EOF

    Private key not provided.
    Please, do generate one by running
    
    openssl rand -hex 32

    $(help)
EOF

exit 1
fi

start() {
    docker rm zilliqa-${ZQ_VERSION} &> /dev/null || echo 0
    docker run -td -p 3333:3333 -p 4201:4201 --net=host --name zilliqa-${ZQ_VERSION} \
    -e RUST_LOG="zilliqa=debug" -e RUST_BACKTRACE=1 \
    -v $(pwd)/$CHAIN_NAME.toml:/config.toml -v /zilliqa.log:/zilliqa.log -v $(pwd)/data:/data \
     $ZQ2_IMAGE $NODE_PRIVATE_KEY --log-json
}

### main ###

start

exit 0