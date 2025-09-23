#!/bin/bash

ZQ_VERSION="{{ version }}"
ZQ2_IMAGE={% if image_tag %}"{{ image_tag }}"{% else %}"asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zq2:${ZQ_VERSION}"{% endif %}
CHAIN_NAME="{{ chain_name }}"

NODE_PRIVATE_KEY=""
CONFIG_FILE="${CHAIN_NAME}.toml"
CHECKPOINT_FILE=""  # The optional checkpoint file to mount, if provided.
DATA_FOLDER=$(pwd)/data
SCILLA_SERVER_PORT=62831

# Define a function to show help using EOF
help() {
    cat <<EOF
        Usage: ${0} -k <node-private-key> [-c <config-file>] [-p <checkpoint-file>]

        Options:
            -k, --key                   NODE_PRIVATE_KEY (mandatory)
            -c, --config                Path to the config file (optional, default: ${CHAIN_NAME}.toml)
            -p, --checkpoint            Path to the checkpoint file (optional, it is needed only the first time a node is started)
                --scilla-server-port    Specify Scilla Server port (WARNING: if set then your consensus.scilla_address config variable must match. eg. "http://localhost:$SCILLA_SERVER_PORT")
            -h, --help                  Display this help message

        Examples:
            ${0} -k <NODE_KEY> -c config.toml -p checkpoint.ckpt (Use .dat for versions prior to v0.19.0)
            ${0} -k <NODE_KEY> -p checkpoint.ckpt (Use .dat for versions prior to v0.19.0)
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
            CHECKPOINT_FILE="$2"
            shift 2
            ;;
        --scilla-server-port)
            SCILLA_SERVER_PORT="$2"
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


if [[ -z "${CHECKPOINT_FILE}" && ! -d "${DATA_FOLDER}" ]]; then
    cat <<-EOF

    Checkpoint not provided.
    Please provide a checkpoint to initialise the node

    $(help)
EOF

exit 1
fi



start() {
    docker rm zilliqa-${ZQ_VERSION} &> /dev/null || echo 0
    if [[ -n "${CHECKPOINT_FILE}" && -f "${CHECKPOINT_FILE}" ]]; then
        # Mount the checkpoint file at /<file_name> inside the container
        MOUNT_OPTION="-v $(pwd)/${CHECKPOINT_FILE}:/$(basename "$CHECKPOINT_FILE")"
    else
        MOUNT_OPTION=""
    fi
    DOCKER_COMMAND="docker run -td \
    -p 3333:3333/udp \
    -p 4201:4201 \
    -p 4202:4202 \
    --net=host \
    --restart=unless-stopped \
    --name zilliqa-${ZQ_VERSION} \
    -e RUST_LOG='zilliqa=debug' \
    -e RUST_BACKTRACE=1 \
    -v $(pwd)/$CONFIG_FILE:/config.toml \
    -v /zilliqa.log:/zilliqa.log \
    -v ${DATA_FOLDER}:/data"

    # Add $MOUNT_OPTION only if it's not empty
    if [[ -n "$MOUNT_OPTION" ]]; then
        DOCKER_COMMAND="$DOCKER_COMMAND $MOUNT_OPTION"
    fi
    DOCKER_COMMAND="$DOCKER_COMMAND $ZQ2_IMAGE $SCILLA_SERVER_PORT $NODE_PRIVATE_KEY --log-json"
    echo "Running Docker command: $DOCKER_COMMAND"
    eval "$DOCKER_COMMAND"
}

### main ###

start

exit 0
