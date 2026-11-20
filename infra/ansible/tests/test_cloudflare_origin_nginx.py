# ABOUTME: Integration test for the Cloudflare origin nginx template used on the apps VM (Otterscan and stats).
# ABOUTME: Renders the Jinja2 template and drives a real nginx in Docker; run: uv run --with pytest --with jinja2 pytest infra/ansible/tests

import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import jinja2
import pytest

TEMPLATES = Path(__file__).resolve().parents[1] / "playbooks" / "templates"
TLS_DIR = "/etc/nginx/cloudflare-origin"
OTTERSCAN = "otterscan.zilliqa.com"
OTTERSCAN_LONG = "otterscan.zq2-mainnet.zilliqa.com"
STATS = "stats.zq2-mainnet.zilliqa.com"
NGINX_IMAGE = "nginx:1.24-alpine"  # same major/minor as Ubuntu 24.04
CURL_IMAGE = "curlimages/curl:8.11.1"

# The http-level SSL directives of Ubuntu 24.04's stock /etc/nginx/nginx.conf, so a duplicate directive fails here too.
UBUNTU_HTTP_DEFAULTS = """
ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
"""

# Stand-ins for the Otterscan (port 80) and stats dashboard (port 3000) containers.
UPSTREAM_STUBS = """
server {
    listen 127.0.0.1:80;
    location / { return 200 "otterscan host=$host proto=$http_x_forwarded_proto\\n"; }
}
server {
    listen 127.0.0.1:3000;
    location / { return 200 "stats host=$host upgrade=$http_upgrade connection=$http_connection\\n"; }
}
"""


def render_config() -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )
    return env.get_template("cloudflare_origin_nginx.conf.j2").render(
        cloudflare_origin_tls_dir=TLS_DIR,
        cloudflare_origin_otterscan_hosts=[OTTERSCAN],
        cloudflare_origin_otterscan_redirect_hosts=[OTTERSCAN_LONG],
        cloudflare_origin_stats_hosts=[STATS],
    )


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check
    )


@pytest.fixture(scope="module")
def nginx(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    if shutil.which("docker") is None or docker("info", check=False).returncode != 0:
        pytest.skip("Docker is not available")

    workdir = tmp_path_factory.mktemp("nginx")
    confd = workdir / "conf.d"
    tls = workdir / "tls"
    confd.mkdir()
    tls.mkdir()
    (confd / "00-ubuntu-defaults.conf").write_text(UBUNTU_HTTP_DEFAULTS)
    (confd / "cloudflare-origin.conf").write_text(render_config())
    (confd / "upstream-stubs.conf").write_text(UPSTREAM_STUBS)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            f"/CN={OTTERSCAN}",
            "-keyout",
            str(tls / "origin.key"),
            "-out",
            str(tls / "origin.pem"),
        ],
        capture_output=True,
        check=True,
    )
    tls.chmod(0o755)
    for pem in tls.iterdir():
        pem.chmod(0o644)

    name = f"cf-origin-test-{uuid.uuid4().hex[:8]}"
    docker(
        "run",
        "-d",
        "--name",
        name,
        "-v",
        f"{confd}:/etc/nginx/conf.d:ro",
        "-v",
        f"{tls}:{TLS_DIR}:ro",
        NGINX_IMAGE,
    )
    try:
        wait_until_serving(name)
        yield name
    finally:
        docker("rm", "-f", name, check=False)


def wait_until_serving(container: str) -> None:
    for _ in range(50):
        probe = docker(
            "exec",
            container,
            "wget",
            "-q",
            "-O",
            "/dev/null",
            "http://127.0.0.1:80/",
            check=False,
        )
        if probe.returncode == 0:
            return
        time.sleep(0.2)
    logs = docker("logs", container, check=False)
    pytest.fail(f"nginx did not start: {logs.stderr}")


def curl(
    container: str, host: str, path: str = "/", *headers: str
) -> subprocess.CompletedProcess[str]:
    header_args = [arg for header in headers for arg in ("-H", header)]
    return docker(
        "run",
        "--rm",
        "--network",
        f"container:{container}",
        CURL_IMAGE,
        "-sk",
        "--max-time",
        "5",
        "--resolve",
        f"{host}:443:127.0.0.1",
        "-o",
        "-",
        "-w",
        "\\n%{http_code} %{redirect_url}",
        *header_args,
        f"https://{host}{path}",
        check=False,
    )


def test_config_is_valid(nginx: str) -> None:
    result = docker("exec", nginx, "nginx", "-t", check=False)
    assert result.returncode == 0, result.stderr


def test_otterscan_is_proxied_to_the_container(nginx: str) -> None:
    result = curl(nginx, OTTERSCAN, "/assets/index.js")
    assert result.returncode == 0, result.stderr
    assert f"otterscan host={OTTERSCAN} proto=https" in result.stdout
    assert result.stdout.rstrip().endswith("200")


def test_long_otterscan_name_redirects_to_the_canonical_one(nginx: str) -> None:
    result = curl(nginx, OTTERSCAN_LONG, "/block/42?tab=txs")
    assert result.returncode == 0, result.stderr
    assert result.stdout.rstrip().endswith(f"301 https://{OTTERSCAN}/block/42?tab=txs")


def test_stats_passes_websocket_upgrade(nginx: str) -> None:
    result = curl(nginx, STATS, "/primus", "Upgrade: websocket", "Connection: Upgrade")
    assert result.returncode == 0, result.stderr
    assert f"stats host={STATS} upgrade=websocket connection=upgrade" in result.stdout


def test_unknown_host_is_refused_at_tls_handshake(nginx: str) -> None:
    result = curl(nginx, "attacker.example.com")
    assert result.returncode != 0, "nginx must not answer for hosts it does not serve"
