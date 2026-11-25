# ABOUTME: Integration test for the node healthcheck service behind the API load balancer (/health on port 8080).
# ABOUTME: Renders the Jinja2 template and drives it against a real JSON-RPC stub; run: uv run --with pytest --with jinja2 --with flask --with requests pytest infra/ansible/tests

import importlib.util
import json
import re
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import jinja2
import pytest

REPO = Path(__file__).resolve().parents[3]
TEMPLATES = REPO / "infra" / "ansible" / "playbooks" / "templates"
API_TF = REPO / "infra" / "tf" / "api.tf"

# Stalls measured on the mainnet API nodes on 2026-11-24 lasted up to 6 s and hit every method at once.
LONGEST_OBSERVED_STALL_SECONDS = 6.0


class JsonRpcStub:
    """A node's JSON-RPC server that answers like zq2 and can freeze the way the API nodes do."""

    def __init__(self) -> None:
        self.stall_until = 0.0
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                time.sleep(max(0.0, stub.stall_until - time.monotonic()))
                result = {"eth_blockNumber": "0x10", "eth_syncing": False}.get(body["method"], "zq2/v0.22.1")
                payload = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the healthcheck gave up waiting

            def log_message(self, *_: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stall_for(self, seconds: float) -> None:
        self.stall_until = time.monotonic() + seconds


@pytest.fixture
def node() -> Iterator[JsonRpcStub]:
    stub = JsonRpcStub()
    yield stub
    stub.server.shutdown()


@pytest.fixture
def healthcheck(tmp_path: Path, node: JsonRpcStub) -> ModuleType:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES), undefined=jinja2.StrictUndefined)
    script = tmp_path / "healthcheck.py"
    script.write_text(env.get_template("healthcheck.py.j2").render(chain_name="zq2-test"))
    spec = importlib.util.spec_from_file_location("healthcheck", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Both the public (4201) and the admin (4202) port are served by the same stub, as they share one runtime.
    module.JSONRPC_PORT = node.port
    module.NODE_URL = f"http://127.0.0.1:{node.port}"
    return module


def get_health(healthcheck: ModuleType) -> tuple[int, float]:
    started = time.monotonic()
    response = healthcheck.app.test_client().get("/health")
    return response.status_code, time.monotonic() - started


def load_balancer_health_check_timeout() -> int:
    block = re.search(r'resource "google_compute_health_check" "api" \{(.*?)\n\}', API_TF.read_text(), re.DOTALL)
    assert block is not None, "google_compute_health_check.api not found in infra/tf/api.tf"
    timeout = re.search(r"^\s*timeout_sec\s*=\s*(\d+)", block.group(1), re.MULTILINE)
    assert timeout is not None, "google_compute_health_check.api has no timeout_sec"
    return int(timeout.group(1))


def test_a_node_that_answers_is_healthy(healthcheck: ModuleType) -> None:
    status, _ = get_health(healthcheck)

    assert status == 200


def test_a_short_stall_does_not_take_the_node_out(healthcheck: ModuleType, node: JsonRpcStub) -> None:
    node.stall_for(3.0)

    status, _ = get_health(healthcheck)

    assert status == 200, "A 3 s freeze of the JSON-RPC runtime is load, not a dead node"


def test_the_longest_observed_stall_does_not_take_the_node_out(healthcheck: ModuleType, node: JsonRpcStub) -> None:
    node.stall_for(LONGEST_OBSERVED_STALL_SECONDS)

    status, elapsed = get_health(healthcheck)

    assert status == 200, "A 6 s freeze of the JSON-RPC runtime is load, not a dead node"
    assert elapsed < load_balancer_health_check_timeout(), "The load balancer would time the probe out first"


def test_a_hung_public_port_is_unhealthy(healthcheck: ModuleType, node: JsonRpcStub) -> None:
    node.stall_for(healthcheck.JSONRPC_TIMEOUT_SECONDS + 5)

    status, elapsed = get_health(healthcheck)

    assert status == 503
    assert elapsed < load_balancer_health_check_timeout(), (
        "The node must answer 503 itself, before the load balancer gives up"
    )


def test_a_closed_public_port_is_unhealthy(healthcheck: ModuleType, node: JsonRpcStub) -> None:
    node.server.shutdown()
    node.server.server_close()

    status, _ = get_health(healthcheck)

    assert status == 503
