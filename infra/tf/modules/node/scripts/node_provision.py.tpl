#! /usr/bin/env python3

import subprocess
import os
import base64
import requests
import sys
from urllib.parse import urlparse

"""
Simple Terraform template of the Python provisioning script 
for the Zilliqa 2.0 validators running on GCP.

templatefile() vars:
- persistence_url, the ZQ2 persistence URL used for recover the network
- conifg, the ZQ2 validators configuration file
- docker_image, the ZQ2 docker image (incl. version)
- secret_key, the ZQ2 node secret key
- role, the node role: validator or apps
- otterscan_image, the Otterscan docker image (incl. version)
- spout_image, the Eth Spout docker image (incl. version)
"""


PERSISTENCE_URL="${persistence_url}"


ZQ2_SCRIPT="""#!/bin/bash
echo yes |  gcloud auth configure-docker asia-docker.pkg.dev,europe-docker.pkg.dev

ZQ2_IMAGE=${docker_image}

docker run -td -p 3333:3333 -p 4201:4201 \
  -e RUST_LOG="zilliqa=debug" -e RUST_BACKTRACE=1 \
  -v /config.toml:/config.toml -v /zilliqa.log:/zilliqa.log -v /data:/data \
  $${ZQ2_IMAGE} $${1} --log-json

exit 0
"""

ZQ2_SERVICE_DESC="""
[Unit]
Description=Zilliqa Node

[Service]
Type=simple
ExecStart=/usr/local/bin/zq2-start.sh ${secret_key}
Environment="RUST_LOG=zilliqa=debug"
Environment="RUST_BACKTRACE=1"
StandardOutput=append:/zilliqa.log

[Install]
WantedBy=multi-user.target
"""

ZQ2_CONFIG="""
${config}
"""

OTTERSCAN_SCRIPT="""#!/bin/bash
echo yes |  gcloud auth configure-docker asia-docker.pkg.dev,europe-docker.pkg.dev

OTTERSCAN_IMAGE=${otterscan_image}

docker run -td -p 80:80 \
    -e ERIGON_URL=https://api.${subdomain} \
    $${OTTERSCAN_IMAGE}

exit 0
"""

OTTERSCAN_SERVICE_DESC="""
[Unit]
Description=Otterscan app

[Service]
Type=simple
ExecStart=/usr/local/bin/otterscan-start.sh

[Install]
WantedBy=multi-user.target
"""

SPOUT_SCRIPT="""#!/bin/bash
echo yes |  gcloud auth configure-docker asia-docker.pkg.dev,europe-docker.pkg.dev

SPOUT_IMAGE=${spout_image}

docker run -td -p 8080:80 \
    -e RPC_URL=https://api.${subdomain} \
    -e NATIVE_TOKEN_SYMBOL="ZIL" \
    -e PRIVATE_KEY="${genesis_key}" \
    -e ETH_AMOUNT=100 \
    -e EXPLORER_URL="https://explorer.${subdomain}" \
    -e MINIMUM_SECONDS_BETWEEN_REQUESTS=60 \
    -e BECH32_HRP="zil" \
    $${SPOUT_IMAGE}

exit 0
"""

SPOUT_SERVICE_DESC="""
[Unit]
Description=Spout app

[Service]
Type=simple
ExecStart=/usr/local/bin/spout-start.sh

[Install]
WantedBy=multi-user.target
"""

OPS_AGENT_INSTALL_SCRIPT_URL="https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh"


OPS_AGENT_CONFIG_FILE="/etc/google-cloud-ops-agent/config.yaml"


OPS_AGENT_CONFIG="""
logging:
  receivers:
    zilliqa:
      type: files
      include_paths:
        - /var/lib/docker/containers/*/*.log
        - /zilliqa.log
  processors:
    parse-log:
        type: parse_json
        field: log
    json:
      type: parse_json
      time_key: timestamp
      time_format: "%Y-%m-%dT%H:%M:%S.%LZ"
    move_fields:
      type: modify_fields
      fields:
        jsonPayload."logging.googleapis.com/severity":
          move_from: jsonPayload.level
        jsonPayload."logging.googleapis.com/sourceLocation".function:
          move_from: jsonPayload.target
  service:
    pipelines:
      zilliqa:
        receivers: [ zilliqa ]
        processors: [ parse-log, json, move_fields ]
"""

LOGROTATE_CONFIG="""
/zilliqa.log
{
    rotate 2
    copytruncate
    delaycompress
    maxsize 256M
    missingok
}
"""

GCLOUD_PUBKEY="""
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=UL8X
-----END PGP PUBLIC KEY BLOCK-----
"""

DOCKER_PUBKEY="""
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
YT90qFF93M3v01BbxP+EIY2/9tiIPbrd
=0YYh
-----END PGP PUBLIC KEY BLOCK-----
"""

INSTALL_PKGS = [ "python3-pip", "pigz" ]


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
    run_or_die(sudo_noninteractive_apt_env(["apt", "update"]))
    run_or_die(sudo_noninteractive_apt_env(["apt", "-y", "dist-upgrade"]))
    a_list = [ "apt" , "install", "-y" ]
    a_list.extend(INSTALL_PKGS)
    run_or_die(sudo_noninteractive_apt_env(a_list))
    install_docker()
    install_ops_agent()
    install_gcloud()
    match role:
        case "validator":
            log("Configuring a validator node")
            configure_logrotate()
            install_zilliqa()
            download_persistence()
            start_zq2()
        case "apps":
            log("Configuring the blockchain app node")
            install_otterscan()
            install_spout()
            start_apps()
        case _:
            log(f"Invalide role {role}")
            log("Provisioning aborted")
            return 1
    log("PROVISIONING_COMPLETED")


def install_ops_agent():
    """
    From https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
    """
    run_or_die(["wget", f"{OPS_AGENT_INSTALL_SCRIPT_URL}"])
    run_or_die(["bash", "add-google-cloud-ops-agent-repo.sh", "--also-install" ])
    with open(OPS_AGENT_CONFIG_FILE, "w") as f:
        f.write(OPS_AGENT_CONFIG)
    run_or_die(sudo_noninteractive_apt_env(["systemctl", "restart", "google-cloud-ops-agent"]))


def install_docker():
    for pkg in [ "docker.io", "docker-doc", "docker-compose", "podman-docker", "runc" ]:
        run_or_die(sudo_noninteractive_apt_env(["apt", "remove", pkg]))
    run_or_die(["sudo", "apt", "install", "-y", "ca-certificates", "curl", "gnupg" ])
    GPG_FILE="/etc/apt/keyrings/docker.gpg"
    the_stats = None
    try:
        the_stats = os.stat(GPG_FILE)
    except:
        pass
    if not os.path.exists("/etc/apt/keyrings/docker.gpg") or the_stats is None or the_stats.st_size == 0:
        try:
            os.makedirs("/etc/apt/keyrings")
        except:
            pass
        the_key = subprocess.Popen(["sudo", "gpg", "--yes", "--batch", "--dearmor", "-o", "/etc/apt/keyrings/docker.gpg"], stdin=subprocess.PIPE)
        the_key.communicate(input=DOCKER_PUBKEY.encode('utf-8'))
    arch = subprocess.check_output(["dpkg", "--print-architecture"]).decode('utf-8').strip()
    codename = subprocess.check_output(["/bin/sh", "-c", ". /etc/os-release && echo \"$VERSION_CODENAME\""]).decode('utf-8').strip()
    print(f"arch $${arch} codename $${codename}")
    with open("/tmp/docker.list", "w") as f:
        f.write(f"deb [arch={arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu {codename} stable\n")
    run_or_die(["sudo", "cp", "/tmp/docker.list", "/etc/apt/sources.list.d/docker.list"])
    run_or_die(sudo_noninteractive_apt_env(["apt", "update"]))
    run_or_die(sudo_noninteractive_apt_env(["sudo","apt", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin" ]))

def install_gcloud():
    run_or_die(["sudo", "apt", "install", "-y", "ca-certificates", "curl", "gnupg" ])
    GPG_FILE="/etc/apt/keyrings/cloud.google.gpg"
    the_stats = None
    try:
        the_stats = os.stat(GPG_FILE)
    except:
        pass
    if not os.path.exists("/etc/apt/keyrings/cloud.google.gpg") or the_stats is None or the_stats.st_size == 0:
        try:
            os.makedirs("/etc/apt/keyrings")
        except:
            pass
        the_key = subprocess.Popen(["sudo", "gpg", "--yes", "--batch", "--dearmor", "-o", "/etc/apt/keyrings/cloud.google.gpg"], stdin=subprocess.PIPE)
        the_key.communicate(input=GCLOUD_PUBKEY.encode('utf-8'))
    with open("/tmp/google-cloud-sdk.list", "w") as f:
        f.write(f"deb https://packages.cloud.google.com/apt cloud-sdk main\n")
    run_or_die(["sudo", "cp", "/tmp/google-cloud-sdk.list", "/etc/apt/sources.list.d/google-cloud-sdk.list"])
    run_or_die(sudo_noninteractive_apt_env(["apt", "update"]))
    run_or_die(sudo_noninteractive_apt_env(["sudo","apt", "install", "-y", "google-cloud-cli" ]))


def create_zq2_start_script():
    with open("/tmp/zq2-start.sh", "w") as f:
        f.write(ZQ2_SCRIPT)
    run_or_die(["sudo", "cp", "/tmp/zq2-start.sh", "/usr/local/bin/zq2-start.sh"])
    run_or_die(["sudo", "chmod", "+x", "/usr/local/bin/zq2-start.sh"])

def install_zilliqa():
    create_zq2_config()
    create_zq2_start_script()
    with open("/tmp/zilliqa.service", "w") as f:
        f.write(ZQ2_SERVICE_DESC)
    run_or_die(["sudo","cp","/tmp/zilliqa.service","/etc/systemd/system/zilliqa.service"])
    run_or_die(["sudo", "chmod", "644", "/etc/systemd/system/zilliqa.service"])
    run_or_die(["sudo", "ln", "-fs", "/etc/systemd/system/zilliqa.service", "/etc/systemd/system/multi-user.target.wants/zilliqa.service"])
    run_or_die(["sudo", "systemctl", "enable", "zilliqa.service"])

def install_otterscan():
    with open("/tmp/otterscan-start.sh", "w") as f:
        f.write(OTTERSCAN_SCRIPT)
    run_or_die(["sudo", "cp", "/tmp/otterscan-start.sh", "/usr/local/bin/otterscan-start.sh"])
    run_or_die(["sudo", "chmod", "+x", "/usr/local/bin/otterscan-start.sh"])
    with open("/tmp/otterscan.service", "w") as f:
        f.write(OTTERSCAN_SERVICE_DESC)
    run_or_die(["sudo","cp","/tmp/otterscan.service","/etc/systemd/system/otterscan.service"])
    run_or_die(["sudo", "chmod", "644", "/etc/systemd/system/otterscan.service"])
    run_or_die(["sudo", "ln", "-fs", "/etc/systemd/system/otterscan.service", "/etc/systemd/system/multi-user.target.wants/otterscan.service"])
    run_or_die(["sudo", "systemctl", "enable", "otterscan.service"])


def install_spout():
    with open("/tmp/spout-start.sh", "w") as f:
        f.write(SPOUT_SCRIPT)
    run_or_die(["sudo", "cp", "/tmp/spout-start.sh", "/usr/local/bin/spout-start.sh"])
    run_or_die(["sudo", "chmod", "+x", "/usr/local/bin/spout-start.sh"])
    with open("/tmp/spout.service", "w") as f:
        f.write(SPOUT_SERVICE_DESC)
    run_or_die(["sudo","cp","/tmp/spout.service","/etc/systemd/system/spout.service"])
    run_or_die(["sudo", "chmod", "644", "/etc/systemd/system/spout.service"])
    run_or_die(["sudo", "ln", "-fs", "/etc/systemd/system/spout.service", "/etc/systemd/system/multi-user.target.wants/spout.service"])
    run_or_die(["sudo", "systemctl", "enable", "spout.service"])


def start_apps():
    run_or_die(["sudo", "systemctl", "start", "otterscan"])
    run_or_die(["sudo", "systemctl", "start", "spout"])


def configure_logrotate():
    with open("/etc/logrotate.d/zilliqa.conf", "w") as f:
        f.write(LOGROTATE_CONFIG)


def create_zq2_config():
    with open("/config.toml", "w") as f:
        f.write(ZQ2_CONFIG)


def download_persistence():
    if PERSISTENCE_URL:
        PERSISTENCE_DIR="/data"
        PERSISTENCE_FILENAME = os.path.basename(urlparse(PERSISTENCE_URL).path)
        os.makedirs(PERSISTENCE_DIR, exist_ok=True)
        run_or_die(["gsutil", "-m", "cp", f"{PERSISTENCE_URL}", f"{PERSISTENCE_DIR}/{PERSISTENCE_FILENAME}"])
        if os.path.exists(PERSISTENCE_DIR):
            os.chdir(PERSISTENCE_DIR)
            run_or_die(["tar", "xf", f"{PERSISTENCE_FILENAME}"])
            run_or_die(["rm", "-f", f"{PERSISTENCE_FILENAME}"])


def start_zq2():
    run_or_die(["sudo", "systemctl", "start", "zilliqa"])


if __name__ == "__main__":
    go(role="${role}")