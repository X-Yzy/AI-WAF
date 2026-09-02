#!/usr/bin/env python3
"""Start the pinned open-appsec benchmark endpoint deterministically.

The official unified image installs the NGINX attachment during its first
startup.  This helper waits for that installation, limits NGINX to one worker
so every replay request uses the same attachment state, reloads NGINX, and
prints the product status.  Persistent state is kept under ``runtime``.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import time


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.yml"
CONTAINER = "wad-openappsec-benchmark"
NGINX_RECOVERY_COMMAND = (
    "pkill -TERM nginx 2>/dev/null || true; "
    "for attempt in 1 2 3 4 5; do "
    "pidof nginx >/dev/null || break; sleep 1; done; "
    "pkill -KILL nginx 2>/dev/null || true; "
    "rm -f /var/run/nginx.pid /run/nginx.pid; nginx"
)


def run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=ROOT,
        env=os.environ.copy(),
        check=check,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )


def wait_until_ready(timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        result = run(
            ["docker", "exec", CONTAINER, "open-appsec-ctl", "--status", "--extended"],
            check=False,
        )
        last = f"{result.stdout}\n{result.stderr}".strip()
        if (
            result.returncode == 0
            and "Policy load status: Success" in last
            and ("Status: Running" in last or "Status: Ready" in last)
        ):
            return last
        time.sleep(2)
    raise RuntimeError(f"open-appsec readiness timeout after {timeout}s\n{last}")



def wait_nginx_ready(timeout: float) -> None:
    """Ensure NGINX is running after the Agent finishes attachment setup.

    The unified image can leave a stale PID after its first attachment reload
    on Docker Desktop.  Once the Agent and policy are ready it is safe to
    remove that PID and start NGINX explicitly; subsequent calls remain
    idempotent because a live master process passes the initial probe.
    """

    probe = (
        "test -s /var/run/nginx.pid && "
        "kill -0 $(cat /var/run/nginx.pid) 2>/dev/null && nginx -t"
    )

    initial = run(
        ["docker", "exec", CONTAINER, "sh", "-c", probe],
        check=False,
    )
    if initial.returncode != 0:
        started = run(
            [
                "docker",
                "exec",
                CONTAINER,
                "sh",
                "-c",
                NGINX_RECOVERY_COMMAND,
            ],
            check=False,
        )
        if started.returncode != 0:
            details = f"{started.stdout}\n{started.stderr}".strip()
            raise RuntimeError(f"open-appsec NGINX failed to start\n{details}")

    deadline = time.monotonic() + timeout
    last = f"{initial.stdout}\n{initial.stderr}".strip()
    while time.monotonic() < deadline:
        result = run(
            ["docker", "exec", CONTAINER, "sh", "-c", probe],
            check=False,
        )
        last = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"open-appsec NGINX readiness timeout after {timeout}s\n{last}")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18083)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=ROOT / "runtime" / "waf_products" / "openappsec",
    )
    args = parser.parse_args()

    state_dir = args.state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["WAD_OPENAPPSEC_PORT"] = str(args.port)
    environment["WAD_OPENAPPSEC_STATE_DIR"] = str(state_dir)
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "up", "-d"],
        cwd=ROOT,
        env=environment,
        check=True,
    )

    wait_until_ready(args.timeout)
    wait_nginx_ready(args.timeout)
    nginx_conf = "/etc/nginx/nginx.conf"
    run(
        [
            "docker",
            "exec",
            CONTAINER,
            "sed",
            "-i",
            "s/^worker_processes auto;/worker_processes 1;/",
            nginx_conf,
        ]
    )
    run(["docker", "exec", CONTAINER, "nginx", "-t"])
    run(["docker", "exec", CONTAINER, "nginx", "-s", "reload"])
    time.sleep(3)
    status = wait_until_ready(args.timeout)
    print("open-appsec benchmark endpoint: READY")
    print(f"URL: http://127.0.0.1:{args.port}")
    print(f"Persistent state: {state_dir}")
    print(status)


if __name__ == "__main__":
    main()
