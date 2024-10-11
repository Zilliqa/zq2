#!/bin/bash

ZQ_VERSION="{{ version }}"
ZQ2_IMAGE="asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zq2:${ZQ_VERSION}"
CHAIN_NAME="{{ chain_name }}"

NODE_PRIVATE_KEY=""
CONFIG_FILE="${CHAIN_NAME}.toml"
OPTIONAL_CHECKPOINT_FILE=""  # The optional checkpoint file to mount, if provided.

# Define a function to show help using EOF
help() {
    cat <<EOF
        Usage: ${0} -k <node-private-key> [-c <config-file>] [-p <checkpoint-file>]

        Options:
            -k, --key           NODE_PRIVATE_KEY (mandatory)
            -c, --config        Path to the config file (optional, default: ${CHAIN_NAME}.toml)
            -p, --checkpoint    Path to the checkpoint file (optional)
            -h, --help          Display this help message

        Examples:
            ${0} -k <NODE_KEY> -c config.toml -p checkpoint.dat
            ${0} -k <NODE_KEY> -p checkpoint.dat
            ${0} -k <NODE_KEY>

EOF
}

# Parse the command-line options
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -k|--key) 
            NODE_PRIVATE_KEY="$2"
            shift 2 
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -p|--checkpoint)
            OPTIONAL_CHECKPOINT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            help
            exit 0 
            ;; 
        *)
            echo "Unknown option: $1"
            help
            exit 1
            ;;
    esac
done


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
    if [[ -n "${OPTIONAL_CHECKPOINT_FILE}" && -f "${OPTIONAL_CHECKPOINT_FILE}" ]]; then
        # Mount the checkpoint file at /<file_name> inside the container
        MOUNT_OPTION="-v $(pwd)/${OPTIONAL_CHECKPOINT_FILE}:/${OPTIONAL_CHECKPOINT_FILE}"
    else
        MOUNT_OPTION=""
    fi
    DOCKER_COMMAND="docker run -td \
    -p 3333:3333/udp \
    -p 4201:4201 \
    --net=host \
    --name zilliqa-${ZQ_VERSION} \
    -e RUST_LOG='zilliqa=debug' \
    -e RUST_BACKTRACE=1 \
    -v $(pwd)/$CHAIN_NAME.toml:/config.toml \
    -v /zilliqa.log:/zilliqa.log \
    -v $(pwd)/data:/data"

    # Add $MOUNT_OPTION only if it's not empty
    if [[ -n "$MOUNT_OPTION" ]]; then
        DOCKER_COMMAND="$DOCKER_COMMAND $MOUNT_OPTION"
    fi
    DOCKER_COMMAND="$DOCKER_COMMAND $ZQ2_IMAGE $NODE_PRIVATE_KEY --log-json"
    echo "Running Docker command: $DOCKER_COMMAND"
    eval "$DOCKER_COMMAND"

}

### main ###

start

exit 0