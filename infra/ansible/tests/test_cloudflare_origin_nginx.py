# ABOUTME: Integration test for the Cloudflare origin nginx template used on the apps VM (Otterscan and stats).
# ABOUTME: Renders the Jinja2 template and drives a real nginx in Docker; run: uv run --with pytest --with jinja2 pytest infra/ansible/tests

import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import jinja2
import pytest

TEMPLATES = Path(__file__).resolve().parents[1] / "playbooks" / "templates"
TLS_DIR = "/etc/nginx/cloudflare-origin"
OTTERSCAN = "otterscan.zilliqa.com"
OTTERSCAN_LONG = "otterscan.zq2-mainnet.zilliqa.com"
STATS = "stats.zq2-mainnet.zilliqa.com"
FAUCET = "faucet.testnet.zilliqa.com"
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
    listen 127.0.0.1:8080;
    location / { return 200 "faucet host=$host client=$http_x_forwarded_for\\n"; }
}
server {
    listen 127.0.0.1:3000;
    location / { return 200 "stats host=$host upgrade=$http_upgrade connection=$http_connection\\n"; }
}
"""


def render_config(**overrides: object) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )
    variables = {
        "cloudflare_origin_tls_dir": TLS_DIR,
        "cloudflare_origin_otterscan_hosts": [OTTERSCAN],
        "cloudflare_origin_otterscan_redirect_hosts": [OTTERSCAN_LONG],
        "cloudflare_origin_stats_hosts": [STATS],
        "cloudflare_origin_faucet_hosts": [FAUCET],
    } | overrides
    return env.get_template("cloudflare_origin_nginx.conf.j2").render(**variables)


def test_renders_without_faucet_or_redirects() -> None:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES), undefined=jinja2.StrictUndefined
    )
    config = env.get_template("cloudflare_origin_nginx.conf.j2").render(
        cloudflare_origin_tls_dir=TLS_DIR,
        cloudflare_origin_otterscan_hosts=[OTTERSCAN],
        cloudflare_origin_otterscan_redirect_hosts=[],
        cloudflare_origin_stats_hosts=[STATS],
    )
    assert "proxy_pass http://127.0.0.1:8080" not in config
    assert "return 301" not in config


@dataclass(frozen=True)
class Origin:
    container: str
    ca_dir: Path


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check
    )


@pytest.fixture(scope="module")
def nginx(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Origin]:
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
    issue_origin_certificate(tls)
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
        yield Origin(container=name, ca_dir=tls)
    finally:
        docker("rm", "-f", name, check=False)


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], capture_output=True, check=True)


def issue_origin_certificate(tls: Path) -> None:
    """A test CA and an origin certificate for every served host, so curl can verify like Full (strict)."""
    ec_key = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes")
    openssl(
        "req",
        "-x509",
        *ec_key,
        "-days",
        "1",
        "-subj",
        "/CN=test origin CA",
        "-keyout",
        str(tls / "ca.key"),
        "-out",
        str(tls / "ca.pem"),
    )
    openssl(
        "req",
        "-new",
        *ec_key,
        "-subj",
        f"/CN={OTTERSCAN}",
        "-keyout",
        str(tls / "origin.key"),
        "-out",
        str(tls / "origin.csr"),
    )
    sans = ",".join(
        f"DNS:{host}" for host in (OTTERSCAN, OTTERSCAN_LONG, STATS, FAUCET)
    )
    (tls / "san.ext").write_text(f"subjectAltName={sans}\n")
    openssl(
        "x509",
        "-req",
        "-days",
        "1",
        "-in",
        str(tls / "origin.csr"),
        "-CA",
        str(tls / "ca.pem"),
        "-CAkey",
        str(tls / "ca.key"),
        "-CAcreateserial",
        "-extfile",
        str(tls / "san.ext"),
        "-out",
        str(tls / "origin.pem"),
    )


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
    origin: Origin, host: str, path: str = "/", *headers: str
) -> subprocess.CompletedProcess[str]:
    header_args = [arg for header in headers for arg in ("-H", header)]
    return docker(
        "run",
        "--rm",
        "--network",
        f"container:{origin.container}",
        "-v",
        f"{origin.ca_dir}:/ca:ro",
        CURL_IMAGE,
        "-s",
        "--cacert",
        "/ca/ca.pem",
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


def test_config_is_valid(nginx: Origin) -> None:
    result = docker("exec", nginx.container, "nginx", "-t", check=False)
    assert result.returncode == 0, result.stderr


def test_otterscan_is_proxied_to_the_container(nginx: Origin) -> None:
    result = curl(nginx, OTTERSCAN, "/assets/index.js")
    assert result.returncode == 0, result.stderr
    assert f"otterscan host={OTTERSCAN} proto=https" in result.stdout
    assert result.stdout.rstrip().endswith("200")


def test_long_otterscan_name_redirects_to_the_canonical_one(nginx: Origin) -> None:
    result = curl(nginx, OTTERSCAN_LONG, "/block/42?tab=txs")
    assert result.returncode == 0, result.stderr
    assert result.stdout.rstrip().endswith(f"301 https://{OTTERSCAN}/block/42?tab=txs")


def test_stats_passes_websocket_upgrade(nginx: Origin) -> None:
    result = curl(nginx, STATS, "/primus", "Upgrade: websocket", "Connection: Upgrade")
    assert result.returncode == 0, result.stderr
    assert f"stats host={STATS} upgrade=websocket connection=upgrade" in result.stdout


def test_unknown_host_is_refused_at_tls_handshake(nginx: Origin) -> None:
    result = curl(nginx, "attacker.example.com")
    # 35 = CURLE_SSL_CONNECT_ERROR: the handshake is rejected, not timed out or answered.
    assert result.returncode == 35, (result.returncode, result.stderr)


def test_faucet_is_proxied_with_the_visitor_ip(nginx: Origin) -> None:
    result = curl(
        nginx,
        FAUCET,
        "/",
        "CF-Connecting-IP: 198.51.100.7",
        "X-Forwarded-For: 203.0.113.66",
    )
    assert result.returncode == 0, result.stderr
    # Replaced, not appended: a client-supplied X-Forwarded-For must not reach the faucet.
    assert f"faucet host={FAUCET} client=198.51.100.7\n" in result.stdout
