"""debug/trace against a real Linux process: IDA's Linux debug server runs
in a container (Docker required; skipped otherwise).  macOS local debugging
needs OS debugging privileges, which tests must not assume."""

import platform
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.ida

IMAGE = "icli-test-linux:1"
DOCKERFILE = Path(__file__).resolve().parents[1] / "docker"
HELLO = r'''#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) { int s = 0; for (int i = 0; i < 3; i++) s += add(i, 2); printf("%d\n", s); return s != 9; }
'''
LOOP = r'''#include <unistd.h>
int tick(int i) { return i + 1; }
int main(void) { int i = 0; for (;;) { i = tick(i); usleep(100000); } }
'''


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def linux(tmp_path_factory):
    if not _docker_ok():
        pytest.skip("docker is not available")
    from icli.cli.env import idadir

    arm = platform.machine().lower() in ("arm64", "aarch64")
    server = idadir() / "dbgsrv" / ("armlinux_server" if arm else "linux_server")
    if not server.exists():
        pytest.skip(f"{server.name} not in this IDA installation")
    work = tmp_path_factory.mktemp("linux")
    shutil.copy(server, work / "server")
    (work / "hello.c").write_text(HELLO)
    (work / "loop.c").write_text(LOOP)
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode:
        subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(DOCKERFILE)], check=True, capture_output=True)
    port = _free_port()
    name = f"icli-test-{port}"
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:{port}",
                    "-v", f"{work}:/w", IMAGE, "sh", "-c",
                    f"gcc -O0 -o hello hello.c && gcc -O0 -o loop loop.c && chmod +x server && "
                    f"./server -p {port}"], check=True, capture_output=True)
    deadline = time.time() + 120
    while time.time() < deadline:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        if "Listening" in logs.stdout + logs.stderr and (work / "loop").exists():
            break
        time.sleep(1)
    else:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        pytest.skip("debug server did not start")
    yield {"work": work, "remote": f"127.0.0.1:{port}", "name": name}
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _run(icli, linux, *args, **kw):
    return icli("-q", "--allow-execute", *args, cwd=linux["work"], **kw)


def test_debug_run_records_breakpoint_hits(icli, linux):
    r = _run(icli, linux, "debug", "run", "--debugger", "linux", "--remote", linux["remote"], "--break", "add",
             "--regs", "x0,x1" if platform.machine().lower() in ("arm64", "aarch64") else "rdi,rsi",
             "--timeout", "60s", "hello")
    assert r.code == 0, r.err
    regs = [list(x["regs"].values()) for x in r.records]
    assert len(regs) == 3 and [int(a, 16) for a, _ in regs] == [0, 1, 2]


def test_trace_coverage_lands_in_coverage_field(icli, linux):
    r = _run(icli, linux, "trace", "--coverage", "--debugger", "linux", "--remote", linux["remote"],
             "--timeout", "60s", "hello")
    assert r.code == 0 and r.records
    f = icli("-q", "list", "functions", "hello", "--match", "add", "--fields", "name,coverage", cwd=linux["work"])
    assert f.record["coverage"] == 3


def test_snapshot_copies_process_memory(icli, linux):
    r = _run(icli, linux, "debug", "snapshot", "--at", "main", "--debugger", "linux", "--remote", linux["remote"],
             "--timeout", "60s", "hello")
    assert r.code == 0 and r.record["taken"]
    segs = icli("-q", "list", "segments", "hello", cwd=linux["work"]).records
    assert any("libc" in s["name"] for s in segs)


def test_attach_times_out_with_10_and_leaves_process_running(icli, linux):
    subprocess.run(["docker", "exec", "-d", linux["name"], "/w/loop"], check=True)
    time.sleep(1)
    pid = subprocess.run(["docker", "exec", linux["name"], "sh", "-c",
                          'for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = loop ] && basename $p; done'],
                         capture_output=True, text=True).stdout.split()[0]
    r = _run(icli, linux, "debug", "attach", "--pid", pid, "--debugger", "linux", "--remote", linux["remote"],
             "--break", "tick", "--timeout", "3s", "loop")
    assert r.code == 10 and r.records
    alive = subprocess.run(["docker", "exec", linux["name"], "test", "-d", f"/proc/{pid}"])
    assert alive.returncode == 0
