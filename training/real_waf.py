"""Real HTTP adapter for the official ModSecurity + OWASP CRS product image."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import secrets
import socket
import subprocess
import threading
import time
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import urlopen
from uuid import uuid4


DEFAULT_IMAGE = "owasp/modsecurity-crs:4.28.0-nginx-202607160307"
PRODUCT_KEY = "modsecurity_crs_4_28_0"
PRODUCT_NAME = "ModSecurity 3.0.16 + OWASP CRS 4.28.0"
OFFICIAL_PROJECT_URL = "https://owasp.org/www-project-modsecurity/"
OFFICIAL_IMAGE_URL = (
    "https://hub.docker.com/r/owasp/modsecurity-crs/tags"
)

_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,62}$")
_RESERVED_HEADERS = {
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "host",
    "transfer-encoding",
}


class RealWAFError(RuntimeError):
    """Raised when the product cannot be started or gives an invalid result."""


@dataclass(frozen=True)
class ProductRequest:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes | None
    original_location: str
    carrier: str
    fallback_reason: str | None = None


@dataclass(frozen=True)
class ProductDecision:
    blocked: bool
    reached_backend: bool
    status_code: int
    elapsed_ms: float


def payload_of(record: dict) -> str:
    return str(record.get("obfuscated_payload") or record.get("payload") or "")


def _parameter_name(record: dict) -> str:
    name = str(record.get("param_name") or "value")
    return "value" if name in {"", "None", "unknown"} else name[:128]


def _safe_header_value(value: str) -> bool:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True


def _safe_header_name(value: str) -> str:
    if (
        not _HEADER_NAME.fullmatch(value)
        or value.lower() in _RESERVED_HEADERS
    ):
        return "X-WAD-Payload"
    return value


def _form_request(
    value: str,
    name: str,
    location: str,
    token: str,
    *,
    fallback_reason: str | None = None,
) -> ProductRequest:
    body = urlencode([(name, value)]).encode("ascii")
    return ProductRequest(
        method="POST",
        target="/benchmark",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
            "X-WAD-Benchmark-Token": token,
        },
        body=body,
        original_location=location,
        carrier="body" if fallback_reason is None else "body_fallback",
        fallback_reason=fallback_reason,
    )


def build_product_request(record: dict, token: str) -> ProductRequest:
    """Map one field-level record into a valid HTTP request for the real WAF."""

    value = payload_of(record)
    name = _parameter_name(record)
    location = str(record.get("param_location") or "query").lower()
    common = {"X-WAD-Benchmark-Token": token}

    if location == "query":
        return ProductRequest(
            "GET",
            "/benchmark?" + urlencode([(name, value)]),
            common,
            None,
            location,
            "query",
        )
    if location == "body":
        return _form_request(value, name, location, token)
    if location == "path":
        return ProductRequest(
            "GET",
            "/benchmark/" + quote(value, safe=""),
            common,
            None,
            location,
            "path",
        )
    if location == "header":
        if _safe_header_value(value):
            headers = {
                **common,
                _safe_header_name(name): value,
            }
            return ProductRequest(
                "GET", "/benchmark", headers, None, location, "header"
            )
        return _form_request(
            value,
            name,
            location,
            token,
            fallback_reason="header value is not representable as one valid HTTP/1.1 field",
        )
    if location == "cookie":
        if _safe_header_value(value):
            return ProductRequest(
                "GET",
                "/benchmark",
                {**common, "Cookie": value},
                None,
                location,
                "cookie",
            )
        return _form_request(
            value,
            name,
            location,
            token,
            fallback_reason="cookie value is not representable as one valid HTTP/1.1 field",
        )
    if location == "filename":
        boundary = "----WADRealWAFBoundary"
        encoded_name = quote(value, safe="")
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; '
            f'filename="benchmark.bin"; filename*=UTF-8\'\'{encoded_name}\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
            "benchmark\r\n"
            f"--{boundary}--\r\n"
        ).encode("ascii")
        return ProductRequest(
            "POST",
            "/benchmark",
            {
                **common,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
            },
            body,
            location,
            "filename",
        )
    return _form_request(
        value,
        name,
        location,
        token,
        fallback_reason=f"unsupported field location: {location}",
    )


class _BackendHandler(BaseHTTPRequestHandler):
    # Close every upstream connection after one proof response. This prevents a
    # single-threaded benchmark backend from being occupied by an idle Nginx
    # keep-alive connection during long runs.
    protocol_version = "HTTP/1.0"
    server_version = "WADBenchmarkBackend/1.0"

    def setup(self) -> None:
        super().setup()
        # A half-open upstream connection must not occupy the single benchmark
        # server forever. Docker Desktop can briefly interrupt host networking
        # while a WAF container is restarted.
        self.connection.settimeout(15.0)

    def _respond(self) -> None:
        expected = getattr(self.server, "benchmark_token")
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        if self.headers.get("X-WAD-Benchmark-Token") != expected:
            self.send_response(404)
            self.send_header("Connection", "close")
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.close_connection = True
            return
        self.send_response(204)
        self.send_header("X-WAD-Benchmark-Backend", "reached")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.close_connection = True

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond
    do_PATCH = _respond

    def log_message(self, _format: str, *args: Any) -> None:
        return


class _BenchmarkHTTPServer(HTTPServer):
    """Sequential proof server that recovers from stalled upstream sockets."""

    request_queue_size = 32

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Socket timeouts are expected infrastructure events. The WAF request
        # itself is retried and audited by the product adapter.
        return


class TemporaryBackend:
    """Short-lived backend that proves whether a request passed the WAF."""

    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(24)
        # The benchmark is deliberately sequential. A single-threaded backend
        # avoids creating tens of thousands of short-lived Windows threads.
        self.server = _BenchmarkHTTPServer(("0.0.0.0", 0), _BackendHandler)
        self.server.benchmark_token = self.token  # type: ignore[attr-defined]
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="real-waf-benchmark-backend",
            daemon=True,
        )
        self.started = False

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def close(self) -> None:
        if self.started:
            self.server.shutdown()
            self.thread.join(timeout=5)
            self.started = False
        self.server.server_close()


def _run_docker(
    arguments: list[str],
    *,
    check: bool = True,
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *arguments],
            check=check,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
        raise RealWAFError(
            f"Docker command failed: docker {' '.join(arguments)}"
            + (f"\n{detail}" if detail else "")
        ) from exc


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ModSecurityCRSProduct:
    """Manage and query an official ModSecurity + CRS Docker container."""

    blocked_statuses = {400, 401, 403, 405, 406, 409, 413, 414, 415, 422, 429}

    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        pull: str = "missing",
        request_timeout: float = 10.0,
        backend: TemporaryBackend | None = None,
    ) -> None:
        self.image = image
        self.pull = pull
        self.request_timeout = request_timeout
        self.container_name = f"wad-real-waf-{uuid4().hex[:12]}"
        self.host_port = _free_loopback_port()
        self.backend = backend or TemporaryBackend()
        self._owns_backend = backend is None
        self.connection: HTTPConnection | None = None
        self.started = False
        self.image_metadata: dict[str, Any] = {}
        self.status_counts: Counter[int] = Counter()
        self.mapping_counts: Counter[str] = Counter()
        self.fallback_counts: Counter[str] = Counter()

    def _ensure_docker(self) -> None:
        _run_docker(["version", "--format", "{{json .Server}}"], timeout=30)
        inspected = _run_docker(
            ["image", "inspect", self.image],
            check=False,
            timeout=30,
        )
        missing = inspected.returncode != 0
        if self.pull == "always" or (self.pull == "missing" and missing):
            _run_docker(["pull", self.image], timeout=900)
        elif missing:
            raise RealWAFError(
                f"Required official WAF image is not available: {self.image}\n"
                f"Run: docker pull {self.image}"
            )
        image_data = json.loads(
            _run_docker(["image", "inspect", self.image], timeout=30).stdout
        )[0]
        self.image_metadata = {
            "id": image_data.get("Id"),
            "repo_digests": image_data.get("RepoDigests", []),
            "created": image_data.get("Created"),
            "architecture": image_data.get("Architecture"),
            "os": image_data.get("Os"),
        }

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 90
        last_error = ""
        while time.monotonic() < deadline:
            try:
                with urlopen(
                    f"http://127.0.0.1:{self.host_port}/healthz",
                    timeout=2,
                ) as response:
                    if response.status == 200:
                        return
            except Exception as exc:  # pragma: no cover - timing dependent
                last_error = str(exc)
            time.sleep(0.5)
        logs = _run_docker(
            ["logs", self.container_name], check=False, timeout=30
        )
        raise RealWAFError(
            f"Official WAF container did not become healthy: {last_error}\n"
            f"{logs.stderr[-4000:] or logs.stdout[-4000:]}"
        )

    def start(self) -> None:
        self._ensure_docker()
        if not self.backend.started:
            self.backend.start()
        command = [
            "run",
            "--detach",
            "--rm",
            "--name",
            self.container_name,
            "--add-host",
            "host.docker.internal:host-gateway",
            "--publish",
            f"127.0.0.1:{self.host_port}:8080",
            "--env",
            f"BACKEND=http://host.docker.internal:{self.backend.port}",
            "--env",
            "PORT=8080",
            "--env",
            "MODSEC_RULE_ENGINE=On",
            "--env",
            "BLOCKING_PARANOIA=1",
            "--env",
            "DETECTION_PARANOIA=1",
            "--env",
            "ANOMALY_INBOUND=5",
            "--env",
            "ANOMALY_OUTBOUND=4",
            "--env",
            "MODSEC_AUDIT_ENGINE=Off",
            "--env",
            "ACCESSLOG=/dev/null",
            "--env",
            "LOGLEVEL=warn",
            self.image,
        ]
        try:
            _run_docker(command, timeout=120)
            self.started = True
            self._wait_ready()
            self._smoke_test()
        except Exception:
            self.close()
            raise

    def _new_connection(self) -> HTTPConnection:
        return HTTPConnection(
            "127.0.0.1",
            self.host_port,
            timeout=self.request_timeout,
        )

    def inspect(self, record: dict) -> ProductDecision:
        request = build_product_request(record, self.backend.token)
        self.mapping_counts[request.carrier] += 1
        if request.fallback_reason:
            self.fallback_counts[request.fallback_reason] += 1

        for attempt in range(2):
            if self.connection is None:
                self.connection = self._new_connection()
            started = time.perf_counter()
            try:
                self.connection.request(
                    request.method,
                    request.target,
                    body=request.body,
                    headers=request.headers,
                )
                response = self.connection.getresponse()
                response.read()
                elapsed_ms = (time.perf_counter() - started) * 1000
                status = int(response.status)
                reached_backend = (
                    status == 204
                    and response.getheader("X-WAD-Benchmark-Backend") == "reached"
                )
                self.status_counts[status] += 1
                if reached_backend:
                    return ProductDecision(False, True, status, elapsed_ms)
                if status in self.blocked_statuses:
                    return ProductDecision(True, False, status, elapsed_ms)
                raise RealWAFError(
                    f"Unexpected WAF response {status} for carrier {request.carrier}"
                )
            except (OSError, TimeoutError) as exc:
                if self.connection is not None:
                    self.connection.close()
                self.connection = None
                if attempt == 1:
                    raise RealWAFError(
                        "Real WAF request failed twice: "
                        f"carrier={request.carrier}, location={request.original_location}, "
                        f"timeout={self.request_timeout}s, error={exc}"
                    ) from exc
        raise AssertionError("unreachable")

    def _smoke_test(self) -> None:
        normal = {
            "payload": "product catalog item 2026",
            "param_location": "query",
            "param_name": "q",
        }
        attack = {
            "payload": "' UNION SELECT password FROM users--",
            "param_location": "query",
            "param_name": "q",
        }
        normal_result = self.inspect(normal)
        attack_result = self.inspect(attack)
        self.status_counts.clear()
        self.mapping_counts.clear()
        self.fallback_counts.clear()
        if normal_result.blocked or not attack_result.blocked:
            raise RealWAFError(
                "Official WAF smoke test failed: expected normal=allowed and SQLi=blocked"
            )

    def identity(self) -> dict[str, Any]:
        return {
            "key": PRODUCT_KEY,
            "name": PRODUCT_NAME,
            "implementation": "official Docker image, real HTTP reverse-proxy execution",
            "is_actual_product_execution": True,
            "is_simulation": False,
            "image": self.image,
            "image_metadata": self.image_metadata,
            "engine": {"name": "ModSecurity", "version": "3.0.16"},
            "ruleset": {"name": "OWASP Core Rule Set", "version": "4.28.0"},
            "web_server": {"name": "Nginx", "version": "1.30.4"},
            "configuration": {
                "rule_engine": "On",
                "blocking_paranoia": 1,
                "detection_paranoia": 1,
                "inbound_anomaly_threshold": 5,
                "outbound_anomaly_threshold": 4,
            },
            "official_sources": [
                OFFICIAL_PROJECT_URL,
                OFFICIAL_IMAGE_URL,
            ],
            "decision_policy": (
                "HTTP request blocked by the running product before reaching "
                "the token-protected benchmark backend"
            ),
            "transport": {
                "endpoint": "loopback-only ephemeral port",
                "backend": "temporary token-protected local HTTP backend",
            },
        }

    def execution_summary(self) -> dict[str, Any]:
        return {
            "container_name": self.container_name,
            "status_codes": {
                str(key): value for key, value in sorted(self.status_counts.items())
            },
            "request_carriers": dict(sorted(self.mapping_counts.items())),
            "fallbacks": dict(sorted(self.fallback_counts.items())),
        }

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.started:
            _run_docker(
                ["rm", "--force", self.container_name],
                check=False,
                timeout=30,
            )
            self.started = False
        if self._owns_backend:
            self.backend.close()

    def __enter__(self) -> "ModSecurityCRSProduct":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class ResilientModSecurityCRSProduct:
    """Replay a failed request on a fresh, identically configured container.

    Infrastructure pauses are never converted into detections. The same record
    must receive a valid product response after restart, and all restart events
    are retained in the report.
    """

    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        pull: str = "missing",
        request_timeout: float = 10.0,
        max_restarts: int = 50,
        max_record_restarts: int = 3,
        max_start_attempts: int = 3,
        start_retry_delay: float = 2.0,
    ) -> None:
        self.image = image
        self.pull = pull
        self.request_timeout = request_timeout
        self.max_restarts = max_restarts
        self.max_record_restarts = max_record_restarts
        self.max_start_attempts = max_start_attempts
        self.start_retry_delay = start_retry_delay
        self.backend = TemporaryBackend()
        self.product: ModSecurityCRSProduct | None = None
        self.identity_snapshot: dict[str, Any] = {}
        self.container_names: list[str] = []
        self.restart_events: list[dict[str, Any]] = []
        self.startup_failures: list[dict[str, Any]] = []
        self.status_counts: Counter[int] = Counter()
        self.mapping_counts: Counter[str] = Counter()
        self.fallback_counts: Counter[str] = Counter()

    def _start_product(self, pull: str) -> None:
        last_error: Exception | None = None
        for attempt in range(1, self.max_start_attempts + 1):
            product = ModSecurityCRSProduct(
                image=self.image,
                pull=pull,
                request_timeout=self.request_timeout,
                backend=self.backend,
            )
            try:
                product.start()
            except Exception as exc:
                last_error = exc
                product.close()
                self.startup_failures.append(
                    {
                        "attempt": attempt,
                        "container_name": product.container_name,
                        "error": str(exc),
                    }
                )
                if attempt < self.max_start_attempts:
                    time.sleep(self.start_retry_delay * attempt)
                continue
            self.product = product
            self.container_names.append(product.container_name)
            if not self.identity_snapshot:
                self.identity_snapshot = product.identity()
            return
        raise RealWAFError(
            "Official WAF could not be started after "
            f"{self.max_start_attempts} attempts: {last_error}"
        ) from last_error

    def _archive_and_close(self) -> None:
        if self.product is None:
            return
        self.status_counts.update(self.product.status_counts)
        self.product.close()
        self.product = None

    def start(self) -> None:
        if not self.backend.started:
            self.backend.start()
        try:
            self._start_product(self.pull)
        except Exception:
            self.backend.close()
            raise

    def inspect(self, record: dict) -> ProductDecision:
        record_restarts = 0
        while True:
            if self.product is None:
                raise RealWAFError("Real WAF product is not running")
            try:
                decision = self.product.inspect(record)
                request = build_product_request(record, self.product.backend.token)
                self.mapping_counts[request.carrier] += 1
                if request.fallback_reason:
                    self.fallback_counts[request.fallback_reason] += 1
                return decision
            except RealWAFError as exc:
                if len(self.restart_events) >= self.max_restarts:
                    raise RealWAFError(
                        f"Real WAF exceeded {self.max_restarts} audited container restarts"
                    ) from exc
                if record_restarts >= self.max_record_restarts:
                    raise RealWAFError(
                        "Real WAF failed deterministically after "
                        f"{self.max_record_restarts} fresh-container replays for "
                        f"record {record.get('id')}"
                    ) from exc
                record_restarts += 1
                self.restart_events.append(
                    {
                        "record_id": str(record.get("id", "")),
                        "label": int(record.get("label", 0)),
                        "attack_type": str(record.get("attack_type", "unknown")),
                        "param_location": str(record.get("param_location", "query")),
                        "record_restart": record_restarts,
                        "global_restart": len(self.restart_events) + 1,
                        "error": str(exc),
                    }
                )
                self._archive_and_close()
                self._start_product("never")

    def identity(self) -> dict[str, Any]:
        return dict(self.identity_snapshot)

    def execution_summary(self) -> dict[str, Any]:
        status_counts = Counter(self.status_counts)
        if self.product is not None:
            status_counts.update(self.product.status_counts)
        return {
            "container_instances": len(self.container_names),
            "container_names": self.container_names,
            "audited_restarts": len(self.restart_events),
            "restart_events": self.restart_events,
            "startup_failures": self.startup_failures,
            "stable_backend_port": self.backend.port,
            "status_codes": {
                str(key): value for key, value in sorted(status_counts.items())
            },
            "request_carriers": dict(sorted(self.mapping_counts.items())),
            "fallbacks": dict(sorted(self.fallback_counts.items())),
        }

    def restore_execution_state(self, state: dict[str, Any]) -> None:
        """Restore only audited counters; a new product container is still used."""

        self.identity_snapshot = dict(state.get("identity", {}))
        self.container_names = list(state.get("container_names", []))
        self.restart_events = list(state.get("restart_events", []))
        self.startup_failures = list(state.get("startup_failures", []))
        self.status_counts = Counter(
            {int(key): int(value) for key, value in state.get("status_codes", {}).items()}
        )
        self.mapping_counts = Counter(
            {str(key): int(value) for key, value in state.get("request_carriers", {}).items()}
        )
        self.fallback_counts = Counter(
            {str(key): int(value) for key, value in state.get("fallbacks", {}).items()}
        )

    def close(self) -> None:
        self._archive_and_close()
        self.backend.close()

    def __enter__(self) -> "ResilientModSecurityCRSProduct":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
