#!/usr/bin/env python3
"""Start and configure the real SafeLine CE benchmark endpoint.

This helper uses the pinned official Compose stack, keeps product state under
``runtime/waf_products/safeline``, waits for all services, and creates one
localhost-only benchmark site that proxies to the proof backend.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
import ssl
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.yml"
REQUIRED_CONTAINERS = (
    "safeline-pg",
    "safeline-mgt",
    "safeline-detector",
    "safeline-tengine",
    "safeline-luigi",
    "safeline-fvm",
    "safeline-chaos",
)


def docker(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        cwd=ROOT,
        check=check,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )


def request_json(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urlopen(request, context=context, timeout=15) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return int(response.status), json.loads(raw or "{}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return int(exc.code), payload


def container_state(name: str) -> dict[str, Any]:
    result = docker(["inspect", name], check=False)
    if result.returncode != 0:
        return {}
    value = json.loads(result.stdout)
    return dict(value[0].get("State", {})) if value else {}


def wait_until_ready(management_url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        states = {name: container_state(name) for name in REQUIRED_CONTAINERS}
        missing = [name for name, state in states.items() if not state.get("Running")]
        management = states["safeline-mgt"]
        health = (management.get("Health") or {}).get("Status")
        if not missing and health == "healthy":
            try:
                status, _ = request_json("GET", f"{management_url}/api/open/health")
                if 200 <= status < 300:
                    return
                last = f"management health HTTP {status}"
            except (OSError, URLError, ValueError) as exc:
                last = str(exc)
        else:
            last = f"not running={missing}, management health={health}"
        time.sleep(3)
    raise RuntimeError(f"SafeLine readiness timeout after {timeout}s: {last}")


def configure_site(
    management_url: str,
    *,
    listen_port: int,
    upstream: str,
) -> None:
    query = urlencode({"page": 1, "page_size": 100})
    status, result = request_json("GET", f"{management_url}/api/Website?{query}")
    if status >= 400:
        raise RuntimeError(f"SafeLine site list failed: HTTP {status}: {result}")
    entries = ((result.get("data") or {}).get("data") or [])
    comment = "WAD real-product benchmark"
    for entry in entries:
        if entry.get("comment") == comment:
            return
    payload = {
        "comment": comment,
        "server_names": ["*"],
        "ports": [str(listen_port)],
        "upstreams": [upstream],
        "cert_filename": "",
        "key_filename": "",
    }
    status, result = request_json("POST", f"{management_url}/api/Website", body=payload)
    if status >= 400 or result.get("err"):
        raise RuntimeError(f"SafeLine site creation failed: HTTP {status}: {result}")



def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


def reset_local_admin() -> tuple[str, str]:
    result = docker(
        ["exec", "safeline-mgt", "/app/mgt-cli", "reset-admin"],
        check=True,
    )
    output = strip_ansi(f"{result.stdout}\n{result.stderr}")
    values: dict[str, str] = {}
    for line in output.splitlines():
        for key, label in (
            ("username", "Initial username"),
            ("password", "Initial password"),
        ):
            if label in line:
                values[key] = re.split(r"[:：]", line, maxsplit=1)[-1].strip()
    if not values.get("username") or not values.get("password"):
        raise RuntimeError("SafeLine reset-admin did not return local credentials")
    return values["username"], values["password"]


def configure_site_with_browser(
    management_url: str,
    *,
    listen_port: int,
    upstream: str,
) -> None:
    """Use SafeLine's normal visible administration form, never session scraping."""

    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
    except ImportError as exc:
        raise RuntimeError(
            "SafeLine v9.3 requires its normal Web UI for initial site creation. "
            "Install project requirements (selenium) or add the site manually."
        ) from exc

    username, password = reset_local_admin()
    options = webdriver.EdgeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--window-size=1600,1200")
    try:
        driver = webdriver.Edge(options=options)
    except Exception:
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--window-size=1600,1200")
        driver = webdriver.Chrome(options=chrome_options)

    try:
        driver.get(f"{management_url}/login")
        time.sleep(2)
        agree = [
            item
            for item in driver.find_elements(By.TAG_NAME, "button")
            if "同意" in item.text and item.is_displayed()
        ]
        if agree:
            driver.execute_script(
                'arguments[0].scrollIntoView({block:"center"})',
                agree[-1],
            )
            agree[-1].click()
            time.sleep(1)
        visible_inputs = [
            item
            for item in driver.find_elements(By.TAG_NAME, "input")
            if item.is_displayed()
        ]
        next(
            item
            for item in visible_inputs
            if item.get_attribute("name") == "username"
        ).send_keys(username)
        next(
            item
            for item in visible_inputs
            if item.get_attribute("name") == "password"
        ).send_keys(password)
        next(
            item
            for item in driver.find_elements(By.TAG_NAME, "button")
            if item.get_attribute("type") == "submit" and item.is_displayed()
        ).click()
        time.sleep(4)
        driver.get(f"{management_url}/sites")
        time.sleep(4)
        add = next(
            item
            for item in driver.find_elements(
                By.XPATH,
                "//*[normalize-space(text())='添加应用']",
            )
            if item.is_displayed()
        )
        driver.execute_script("arguments[0].click()", add)
        time.sleep(2)
        port = driver.find_element(By.NAME, "ports.0.port")
        port.clear()
        port.send_keys(str(listen_port))
        second_port = driver.find_element(By.NAME, "ports.1.port")
        row = driver.execute_script(
            "return arguments[0].parentElement.parentElement.parentElement",
            second_port,
        )
        driver.execute_script(
            "arguments[0].click()",
            row.find_elements(By.TAG_NAME, "button")[-1],
        )
        driver.find_element(By.NAME, "upstreams.0.upstream").send_keys(upstream)
        driver.find_element(By.NAME, "comment").send_keys(
            "WAD real-product benchmark"
        )
        submit = next(
            item
            for item in driver.find_elements(
                By.XPATH,
                "//button[normalize-space(text())='提交']",
            )
            if item.is_displayed()
        )
        driver.execute_script("arguments[0].click()", submit)
        time.sleep(8)
        if "WAD real-product benchmark" not in driver.find_element(
            By.TAG_NAME, "body"
        ).text:
            raise RuntimeError("SafeLine UI did not confirm benchmark site creation")
    finally:
        driver.quit()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18082)
    parser.add_argument("--management-port", type=int, default=19443)
    parser.add_argument("--upstream", default="http://host.docker.internal:18081")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=ROOT / "runtime" / "waf_products" / "safeline",
    )
    args = parser.parse_args()

    state_dir = args.state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "SAFELINE_DIR": str(state_dir),
            "POSTGRES_PASSWORD": environment.get(
                "WAD_SAFELINE_POSTGRES_PASSWORD",
                "WADSafeLineBench2026",
            ),
            "MGT_PORT": str(args.management_port),
            "WAD_SAFELINE_PORT": str(args.port),
            "RELEASE": "",
            "CHANNEL": "",
            "REGION": "",
            "IMAGE_PREFIX": environment.get(
                "WAD_SAFELINE_IMAGE_PREFIX",
                "swr.cn-east-3.myhuaweicloud.com/chaitin-safeline",
            ),
            "IMAGE_TAG": environment.get("WAD_SAFELINE_IMAGE_TAG", "latest"),
            "SUBNET_PREFIX": environment.get("WAD_SAFELINE_SUBNET", "172.27.52"),
            "ARCH_SUFFIX": "",
        }
    )
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "up", "-d"],
        cwd=ROOT,
        env=environment,
        check=True,
    )
    management_url = f"https://127.0.0.1:{args.management_port}"
    wait_until_ready(management_url, args.timeout)
    site_pattern = f"listen 0.0.0.0:{args.port} "
    site_files = list(
        (state_dir / "resources" / "nginx" / "sites-enabled").glob(
            "IF_backend_*"
        )
    )
    site_ready = any(
        site_pattern in item.read_text(encoding="utf-8", errors="replace")
        for item in site_files
        if item.is_file()
    )
    if not site_ready:
        try:
            configure_site(
                management_url,
                listen_port=args.port,
                upstream=args.upstream,
            )
        except RuntimeError as exc:
            if "HTTP 404" not in str(exc) and "HTTP 401" not in str(exc):
                raise
            configure_site_with_browser(
                management_url,
                listen_port=args.port,
                upstream=args.upstream,
            )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = docker(
            [
                "exec",
                "safeline-tengine",
                "sh",
                "-c",
                f"test -f /etc/nginx/sites-enabled/IF_backend_1 && nginx -t",
            ],
            check=False,
        )
        if result.returncode == 0:
            break
        time.sleep(2)
    else:
        raise RuntimeError("SafeLine site configuration was not published to Tengine")

    version = docker(
        ["exec", "safeline-mgt", "/app/mgt-cli", "version"],
        check=False,
    )
    print("SafeLine CE benchmark endpoint: READY")
    print(f"URL: http://127.0.0.1:{args.port}")
    print(f"Management: {management_url} (localhost only)")
    print(f"Persistent state: {state_dir}")
    print((version.stdout or version.stderr).strip())


if __name__ == "__main__":
    main()
