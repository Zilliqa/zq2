# ABOUTME: Integration test for the Cloudflare origin nginx template used on the apps VM (Otterscan, stats, faucet).
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


def start_origin(
    tmp_path_factory: pytest.TempPathFactory, **overrides: object
) -> Iterator[Origin]:
    if shutil.which("docker") is None or docker("info", check=False).returncode != 0:
        pytest.skip("Docker is not available")

    workdir = tmp_path_factory.mktemp("nginx")
    confd = workdir / "conf.d"
    tls = workdir / "tls"
    confd.mkdir()
    tls.mkdir()
    (confd / "00-ubuntu-defaults.conf").write_text(UBUNTU_HTTP_DEFAULTS)
    (confd / "cloudflare-origin.conf").write_text(render_config(**overrides))
    (confd / "upstream-stubs.conf").write_text(UPSTREAM_STUBS)
    issue_origin_certificate(tls)
    issue_client_certificate(tls, "cloudflare-aop-ca", "client")
    issue_client_certificate(tls, "other-ca", "other-client")
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


@pytest.fixture(scope="module")
def nginx(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Origin]:
    yield from start_origin(tmp_path_factory)


@pytest.fixture(scope="module")
def nginx_aop(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Origin]:
    """Authenticated Origin Pulls enforced: only our Cloudflare client certificate gets through."""
    yield from start_origin(tmp_path_factory, cloudflare_origin_client_verify="on")


@pytest.fixture(scope="module")
def nginx_aop_staging(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Origin]:
    """Authenticated Origin Pulls staged: every request is served and the verification result is logged."""
    yield from start_origin(
        tmp_path_factory, cloudflare_origin_client_verify="optional"
    )


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


def issue_client_certificate(tls: Path, ca: str, client: str) -> None:
    """A CA and a client certificate signed by it, like the pair whose leaf Cloudflare presents to the origin."""
    ec_key = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes")
    openssl(
        "req",
        "-x509",
        *ec_key,
        "-days",
        "1",
        "-subj",
        f"/CN={ca}",
        "-keyout",
        str(tls / f"{ca}.key"),
        "-out",
        str(tls / f"{ca}.pem"),
    )
    openssl(
        "req",
        "-new",
        *ec_key,
        "-subj",
        f"/CN={client}",
        "-keyout",
        str(tls / f"{client}.key"),
        "-out",
        str(tls / f"{client}.csr"),
    )
    (tls / f"{client}.ext").write_text(
        "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n"
    )
    openssl(
        "x509",
        "-req",
        "-days",
        "1",
        "-in",
        str(tls / f"{client}.csr"),
        "-CA",
        str(tls / f"{ca}.pem"),
        "-CAkey",
        str(tls / f"{ca}.key"),
        "-CAcreateserial",
        "-extfile",
        str(tls / f"{client}.ext"),
        "-out",
        str(tls / f"{client}.pem"),
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
    origin: Origin,
    host: str,
    path: str = "/",
    *headers: str,
    client_cert: str | None = None,
) -> subprocess.CompletedProcess[str]:
    header_args = [arg for header in headers for arg in ("-H", header)]
    cert_args = (
        ["--cert", f"/ca/{client_cert}.pem", "--key", f"/ca/{client_cert}.key"]
        if client_cert
        else []
    )
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
        *cert_args,
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


def test_origin_pulls_are_not_required_by_default() -> None:
    config = render_config()
    assert "ssl_verify_client" not in config


def aop_log(origin: Origin) -> str:
    return docker(
        "exec", origin.container, "cat", "/var/log/nginx/cloudflare-origin-aop.log"
    ).stdout


def test_origin_pulls_config_is_valid(nginx_aop: Origin) -> None:
    result = docker("exec", nginx_aop.container, "nginx", "-t", check=False)
    assert result.returncode == 0, result.stderr


def test_origin_pulls_let_our_cloudflare_certificate_through(nginx_aop: Origin) -> None:
    for host in (OTTERSCAN, STATS, FAUCET):
        result = curl(nginx_aop, host, client_cert="client")
        assert result.returncode == 0, result.stderr
        assert result.stdout.rstrip().endswith("200"), (host, result.stdout)


def test_origin_pulls_keep_the_redirect(nginx_aop: Origin) -> None:
    result = curl(nginx_aop, OTTERSCAN_LONG, "/tx/1", client_cert="client")
    assert result.returncode == 0, result.stderr
    assert result.stdout.rstrip().endswith(f"301 https://{OTTERSCAN}/tx/1")


def test_origin_pulls_keep_the_stats_websocket(nginx_aop: Origin) -> None:
    result = curl(
        nginx_aop,
        STATS,
        "/primus",
        "Upgrade: websocket",
        "Connection: Upgrade",
        client_cert="client",
    )
    assert result.returncode == 0, result.stderr
    assert f"stats host={STATS} upgrade=websocket connection=upgrade" in result.stdout


def test_origin_pulls_keep_refusing_unknown_hosts(nginx_aop: Origin) -> None:
    result = curl(nginx_aop, "attacker.example.com", client_cert="client")
    assert result.returncode == 35, (result.returncode, result.stderr)


def test_origin_pulls_refuse_a_request_without_a_certificate(nginx_aop: Origin) -> None:
    # Another Cloudflare account pointed at the VM sends no certificate, or Cloudflare's shared one.
    for host in (OTTERSCAN, STATS, FAUCET):
        result = curl(nginx_aop, host)
        assert result.returncode == 0, result.stderr
        assert "No required SSL certificate was sent" in result.stdout, host
        assert result.stdout.rstrip().endswith("400"), (host, result.stdout)


def test_origin_pulls_refuse_a_certificate_from_another_ca(nginx_aop: Origin) -> None:
    result = curl(nginx_aop, FAUCET, client_cert="other-client")
    assert result.returncode == 0, result.stderr
    assert "The SSL certificate error" in result.stdout
    assert result.stdout.rstrip().endswith("400"), result.stdout


def test_staged_origin_pulls_serve_and_log_the_result(
    nginx_aop_staging: Origin,
) -> None:
    without = curl(nginx_aop_staging, FAUCET)
    with_ours = curl(nginx_aop_staging, OTTERSCAN, client_cert="client")
    assert without.stdout.rstrip().endswith("200"), without.stdout
    assert with_ours.stdout.rstrip().endswith("200"), with_ours.stdout
    log = aop_log(nginx_aop_staging)
    assert f" {FAUCET} NONE 200" in log, log
    assert f" {OTTERSCAN} SUCCESS 200" in log, log
