#! /usr/bin/env python3

import subprocess
import os
import base64
import json
import requests
import sys
from urllib.parse import urlparse

"""
Simple Terraform template of the Python provisioning script 
for the Zilliqa 2.0 validators running on GCP.

templatefile() vars:
- checkpoint_url, the ZQ2 checkpoint URL used for recover the validator nodes
- persistence_url, the ZQ2 persistence URL used for recover the network
- docker_image, the ZQ2 docker image (incl. version)
- role, the node role: api, checkpoint, persistence, private-api or bootstrap
- enable_kms, a flag to enable the KMS decryption for the keys
- log_level, the ZQ2 network service log level
- project_id, id of the GCP project
- chain_name, name of the ZQ2 chain
- node_name, name of the ZQ2 node
"""

def query_metadata_key(key: str) -> str:
    try:
        url = f"http://metadata.google.internal/computeMetadata/v1/instance/attributes/{key}"
        r = requests.get(url, headers={"Metadata-Flavor": "Google"})
        value = r.text
        try:
            value = base64.b64decode(value).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            print(f"Warning: Failed to decode base64 value for key {key}")
            return ""
        return value
    except Exception:
        print(f"Metadata key not found {key}")
        return ""

ZQ2_IMAGE="{{ docker_image }}"
PERSISTENCE_URL="{{ persistence_url }}"
CHECKPOINT_URL="{{ checkpoint_url }}"
NODE_NAME="{{ node_name }}"
PROJECT_ID="{{ project_id }}"
KMS_ENABLED="{{ enable_kms }}" == "true"
KMS_PROJECT_ID = "prj-p-kms-2vduab0g" if PROJECT_ID.startswith("prj-p") else "prj-d-kms-tw1xyxbh"

# Set zilliqa trace log level for specific nodes, if not use the default
if NODE_NAME in [
    "zq2-testnet-api-ase1-0",
    "zq2-testnet-validator-ase1-0",
    "zq2-mainnet-api-ase1-0",
    "zq2-mainnet-bootstrap-ase1-0",
    "zq2-mainnet-checkpoint-ase1-0",
    "zq2-mainnet-persistence-ase1-0",
    "zq2-mainnet-apps-ase1-0",
]:
    LOG_LEVEL = "zilliqa=trace"
else:
    LOG_LEVEL = '{{ log_level }}'

def mount_checkpoint_file():
    if CHECKPOINT_URL is not None and CHECKPOINT_URL != "":
        CHECKPOINT_FILENAME = os.path.basename(urlparse(CHECKPOINT_URL).path)
        return f"-v /tmp/{CHECKPOINT_FILENAME}:/{CHECKPOINT_FILENAME}"
    return ""

VERSIONS={
    "zilliqa": ZQ2_IMAGE.split(":")[-1] if ZQ2_IMAGE.split(":")[-1] else "latest",
}

def query_metadata_ext_ip() -> str:
    url = f"http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
    r = requests.get(url, headers = {
        "Metadata-Flavor" : "Google" })
    return r.text

SCILLA_SERVER_PORT="62831"

if KMS_ENABLED:
    PRIVATE_KEY_CMD = '$(gcloud secrets versions access latest --project="{{ project_id }}" --secret="{{ node_name }}-enckey" | base64 -d | gcloud kms decrypt --ciphertext-file=- --plaintext-file=- --key="{{ node_name }}" --keyring="kms-{{ chain_name }}" --location=global --project="' + KMS_PROJECT_ID + '")'
else:
    PRIVATE_KEY_CMD = '$(gcloud secrets versions access latest --project="{{ project_id }}" --secret="{{ node_name }}-pk")'

REDIS_ENDPOINT_CMD = '$(gcloud secrets versions access latest --project="{{ project_id }}" --secret="{{ chain_name }}-redis-endpoint" 2>/dev/null || echo "")'

# Execute the gcloud command to get rate limit configuration
def get_rate_limit_config():
    try:
        cmd = ['gcloud', 'secrets', 'versions', 'access', 'latest', 
               '--project', PROJECT_ID, 
               '--secret', '{{ chain_name }}-rate-limit-bypass']
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
    except (subprocess.CalledProcessError, json.JSONDecodeError, Exception):
        pass
    return {}

rate_limit_config = get_rate_limit_config()
RATE_LIMIT_IPS = ",".join(rate_limit_config.get("ips", []))
RATE_LIMIT_API_KEYS = ",".join(rate_limit_config.get("api_keys", []))

def build_rate_limit_env_vars():
    """Build docker -e flags for rate limit env vars only if they are defined and non-empty"""
    env_vars = []
    if RATE_LIMIT_IPS and RATE_LIMIT_IPS.strip():
        env_vars.append(f"-e ALLOWED_IPS={RATE_LIMIT_IPS}")
    if RATE_LIMIT_API_KEYS and RATE_LIMIT_API_KEYS.strip():
        env_vars.append(f"-e ALLOWED_KEYS={RATE_LIMIT_API_KEYS}")
    if env_vars:
        return " ".join(env_vars)
    return ""

ZQ2_SCRIPT="""#!/bin/bash
echo yes | gcloud auth configure-docker asia-docker.pkg.dev,europe-docker.pkg.dev

ZQ2_IMAGE="{{ docker_image }}"

start() {
    docker rm zilliqa-""" + VERSIONS.get('zilliqa') + """ &> /dev/null || echo 0
    docker run --ulimit nofile=1000000:1000000 -td -p 3333:3333/udp -p 4201:4201 -p 4202:4202 --cap-add=SYS_PTRACE --cap-add=PERFMON --cap-add=BPF --cap-add=SYS_ADMIN \
        --net=host --name zilliqa-""" + VERSIONS.get('zilliqa') + """ \
        -v /config.toml:/config.toml -v /zilliqa.log:/zilliqa.log -v /data:/data \
        --log-driver json-file --log-opt max-size=1g --log-opt max-file=1 --memory=6g \
        -e RUST_LOG='""" + LOG_LEVEL + """' -e OTEL_METRIC_EXPORT_INTERVAL=60000 -e RUST_BACKTRACE=1 \
        -e REDIS_ENDPOINT=""" + REDIS_ENDPOINT_CMD + """ \
        -e SECRET_KEY=""" + PRIVATE_KEY_CMD + """ \
        """ + build_rate_limit_env_vars() + """ \
        --restart=unless-stopped \
    """ + mount_checkpoint_file() + """ ${ZQ2_IMAGE} """ + SCILLA_SERVER_PORT + """ --log-json
    docker system prune -a -f --volumes
}

stop() {
    docker stop -t 60 --signal SIGINT zilliqa-""" + VERSIONS.get('zilliqa') + """
}

case ${1} in
    start|stop) ${1} ;;
esac

exit 0
"""

ZQ2_SERVICE_DESC="""
[Unit]
Description=Zilliqa Node

[Service]
Type=forking
ExecStart=/usr/local/bin/zq2.sh start
ExecStop=/usr/local/bin/zq2.sh stop
RemainAfterExit=yes
Restart=on-failure
RestartSec=10
StandardOutput=append:/zilliqa.log

[Install]
WantedBy=multi-user.target
"""

def log(val):
    with open("/tmp/startup-log.txt", 'w+') as f:
        f.write(val)
        f.write("\n")

def run_or_die(args, env = None):
    the_args = " ".join(args)
    printable = f"{the_args}"
    print(f"> {printable}")
    subprocess.check_call(args, env = env)

def sudo_noninteractive_apt_env(rest):
    result = [
        "sudo",
        "DEBIAN_FRONTEND=noninteractive",
        "NEEDRESTART_MODE=a"
    ]
    result.extend(rest)
    return result

def go(role):
    log("Running as {0}".format(os.getuid()))
    login_registry()
    match role:
        case "api" | "checkpoint" | "persistence" | "private-api" :
            log("Configuring a not validator node")
            pull_zq2_image()
            stop_zq2()
            install_zilliqa()
            download_persistence()
            download_checkpoint()
            start_zq2()
        case "bootstrap" | "validator":
            log("Configuring a validator node")
            pull_zq2_image()
            stop_zq2()
            install_zilliqa()
            download_persistence()
            download_checkpoint()
            start_zq2()
        case _:
            log(f"Invalide role {role}")
            log("Provisioning aborted")
            return 1
    log("PROVISIONING_COMPLETED")

def login_registry():
    run_or_die(["sudo", "bash", "-c", "gcloud auth application-default print-access-token | docker login -u oauth2accesstoken --password-stdin https://asia-docker.pkg.dev" ])

def create_zq2_start_script():
    with open("/tmp/zq2.sh", "w") as f:
        f.write(ZQ2_SCRIPT)
    run_or_die(["sudo", "cp", "/tmp/zq2.sh", f"/usr/local/bin/zq2-{VERSIONS.get('zilliqa')}.sh"])
    run_or_die(["sudo", "chmod", "+x", f"/usr/local/bin/zq2-{VERSIONS.get('zilliqa')}.sh"])
    run_or_die(["sudo", "ln", "-fs", f"/usr/local/bin/zq2-{VERSIONS.get('zilliqa')}.sh", "/usr/local/bin/zq2.sh"])

def install_zilliqa():
    create_zq2_start_script()
    with open("/tmp/zilliqa.service", "w") as f:
        f.write(ZQ2_SERVICE_DESC)
    run_or_die(["sudo","cp","/tmp/zilliqa.service","/etc/systemd/system/zilliqa.service"])
    run_or_die(["sudo", "chmod", "644", "/etc/systemd/system/zilliqa.service"])
    run_or_die(["sudo", "ln", "-fs", "/etc/systemd/system/zilliqa.service", "/etc/systemd/system/multi-user.target.wants/zilliqa.service"])
    run_or_die(["sudo", "systemctl", "enable", "zilliqa.service"])

def download_persistence_file():
    if PERSISTENCE_URL is not None and PERSISTENCE_URL != "":
        PERSISTENCE_DIR="/data"
        run_or_die(["rm", "-rf", f"{PERSISTENCE_DIR}"])
        PERSISTENCE_FILENAME = os.path.basename(urlparse(PERSISTENCE_URL).path)
        os.makedirs(PERSISTENCE_DIR, exist_ok=True)
        run_or_die(["gsutil", "-m", "cp", f"{PERSISTENCE_URL}", f"{PERSISTENCE_DIR}/{PERSISTENCE_FILENAME}"])
        if os.path.exists(PERSISTENCE_DIR):
            os.chdir(PERSISTENCE_DIR)
            run_or_die(["tar", "xf", f"{PERSISTENCE_FILENAME}"])
            run_or_die(["rm", "-f", f"{PERSISTENCE_FILENAME}"])

def download_persistence_folder():
    if PERSISTENCE_URL is not None and PERSISTENCE_URL != "":
        PERSISTENCE_DIR="/data"
        run_or_die(["sudo", "rm", "-rf", f"{PERSISTENCE_DIR}"])
        os.makedirs(PERSISTENCE_DIR, exist_ok=True)
        run_or_die(["sudo", "gsutil", "-m", "cp", "-r", f"{PERSISTENCE_URL}/*", f"{PERSISTENCE_DIR}"])

def download_persistence():
    if PERSISTENCE_URL is not None and PERSISTENCE_URL != "":
        if PERSISTENCE_URL.endswith(".tar.gz"):
            download_persistence_file()
        else:
            download_persistence_folder()

def download_checkpoint():
    if CHECKPOINT_URL is not None and CHECKPOINT_URL != "":
        PERSISTENCE_DIR="/data"
        run_or_die(["rm", "-rf", f"{PERSISTENCE_DIR}"])
        os.makedirs(PERSISTENCE_DIR, exist_ok=True)
        CHECKPOINT_FILENAME = os.path.basename(urlparse(CHECKPOINT_URL).path)
        run_or_die(["gsutil", "-m", "cp", f"{CHECKPOINT_URL}", f"/tmp/{CHECKPOINT_FILENAME}"])

def start_zq2():
    run_or_die(["sudo", "systemctl", "start", "zilliqa"])

def pull_zq2_image():
    run_or_die(["sudo", "docker", "pull", f"{ZQ2_IMAGE}"])

def stop_zq2():
    if os.path.exists("/etc/systemd/system/zilliqa.service"):
        run_or_die(["sudo", "systemctl", "stop", "zilliqa"])
    pass

if __name__ == "__main__":
    go(role="{{ role }}")
