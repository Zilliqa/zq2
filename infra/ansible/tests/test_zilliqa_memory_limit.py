# ABOUTME: Integration test for the zilliqa container memory limit set by zq2.sh, sized from the host's RAM.
# ABOUTME: Renders the Jinja2 template and runs `start` against stub docker/gcloud; run: uv run --with pytest --with jinja2 pytest infra/ansible/tests

import re
import subprocess
from pathlib import Path

import jinja2
import pytest

REPO = Path(__file__).resolve().parents[3]
ANSIBLE_SCRIPT = REPO / "infra" / "ansible" / "playbooks" / "templates" / "zilliqa.sh.j2"
Z2_PROVISIONING = REPO / "z2" / "resources" / "node_provision.tera.py"

# MemTotal as the kernel reports it on the GCE machine types the nodes run on.
E2_STANDARD_2_KB = 8_148_936  # 8 GB: bootstrap, opsnode, private API
E2_STANDARD_4_KB = 16_369_124  # 16 GB: public API nodes, where 6 GiB starved RocksDB of page cache (2026-11-27)


def docker_run_args(tmp_path: Path, mem_total_kb: int) -> str:
    script = tmp_path / "zq2.sh"
    # trim_blocks as ansible's template module does: otherwise each {% if %} leaves a blank line that breaks the
    # backslash continuation of the docker run command.
    script.write_text(
        jinja2.Environment(trim_blocks=True)
        .from_string(ANSIBLE_SCRIPT.read_text())
        .render(
            zq2_image="zq2:test",
            zq2_version="v0.0.0",
            log_level="info",
            redis_endpoint="",
            zq2_private_key="key",
        )
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "docker-calls"
    for name, body in {"docker": f'echo "$*" >> {calls}', "gcloud": "cat > /dev/null"}.items():
        stub = bin_dir / name
        stub.write_text(f"#!/bin/bash\n{body}\n")
        stub.chmod(0o755)
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(f"MemTotal:       {mem_total_kb} kB\nMemFree:          123456 kB\n")

    subprocess.run(
        ["bash", str(script), "start"],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "MEMINFO": str(meminfo)},
        check=True,
    )
    return next(line for line in calls.read_text().splitlines() if line.startswith("run "))


@pytest.mark.parametrize(
    ("mem_total_kb", "expected"),
    [
        (E2_STANDARD_2_KB, "--memory=6144m"),  # unchanged from the old fixed 6g
        (E2_STANDARD_4_KB, "--memory=11889m"),  # all but 4 GiB of the host
    ],
)
def test_container_memory_limit_follows_host_ram(tmp_path: Path, mem_total_kb: int, expected: str) -> None:
    assert expected in docker_run_args(tmp_path, mem_total_kb).split()


def test_z2_provisioning_sizes_the_limit_the_same_way() -> None:
    """mainnet is provisioned by z2, not ansible: both must size the container identically."""
    function = re.compile(r"container_memory_limit_mb\(\) \{.*?\n\}", re.DOTALL)
    ansible = function.search(ANSIBLE_SCRIPT.read_text())
    z2 = function.search(Z2_PROVISIONING.read_text())
    assert ansible and z2, "both scripts must define container_memory_limit_mb"
    assert ansible.group() == z2.group()
    assert "--memory=6g" not in Z2_PROVISIONING.read_text()
