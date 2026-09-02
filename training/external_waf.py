"""Adapters for real SafeLine and open-appsec reverse-proxy benchmarks.

These products are deliberately not simulated.  Operators deploy the real WAF
and configure its upstream to the benchmark echo backend documented in
``docs/deployment/WAF_BENCHMARK.md``.  This adapter then replays exactly the
same HTTP requests used for ModSecurity and requires an explicit backend proof
header before an unblocked request is accepted.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException, HTTPSConnection
import secrets
import time
from typing import Any
from urllib.parse import urlsplit

from training.real_waf import (
    ProductDecision,
    RealWAFError,
    build_product_request,
)


SAFELINE_KEY = "safeline_ce"
OPENAPPSEC_KEY = "openappsec_ce"


@dataclass(frozen=True)
class ExternalProductSpec:
    """Operator-supplied identity for one independently deployed WAF."""

    key: str
    name: str
    endpoint: str
    version: str
    project_url: str
    deployment_note: str


PRODUCT_CATALOG = {
    SAFELINE_KEY: {
        "display_name": "SafeLine 社区版",
        "vendor": "长亭科技",
        "kind": "real_waf_product",
        "project_url": "https://github.com/chaitin/SafeLine",
        "endpoint_env": "WAD_SAFELINE_URL",
        "version_env": "WAD_SAFELINE_VERSION",
        "deployment_note": "真实 SafeLine 反向代理端点；上游必须指向基准回显后端",
    },
    OPENAPPSEC_KEY: {
        "display_name": "open-appsec 社区版",
        "vendor": "open-appsec",
        "kind": "real_waf_product",
        "project_url": "https://github.com/openappsec/openappsec",
        "endpoint_env": "WAD_OPENAPPSEC_URL",
        "version_env": "WAD_OPENAPPSEC_VERSION",
        "deployment_note": "真实 open-appsec NGINX/Agent 端点；策略必须为 prevent 模式",
    },
}


def candidate_statuses(
    configured: dict[str, ExternalProductSpec],
) -> dict[str, dict[str, Any]]:
    """Describe configured and missing products without inventing metrics."""

    result: dict[str, dict[str, Any]] = {}
    for key, metadata in PRODUCT_CATALOG.items():
        spec = configured.get(key)
        if spec:
            result[key] = {
                **metadata,
                "status": "configured",
                "configured": True,
                "included_in_ranking": False,
                "version": spec.version,
                "reason": "已配置真实产品端点，等待完成同集评测",
            }
        else:
            result[key] = {
                **metadata,
                "status": "not_configured",
                "configured": False,
                "included_in_ranking": False,
                "version": None,
                "reason": (
                    f"未设置 {metadata['endpoint_env']}；未运行真实产品，"
                    "因此不生成或展示效果指标"
                ),
            }
    return result


class ExternalReverseProxyWAF:
    """Inspect records through a real, operator-managed reverse-proxy WAF."""

    blocked_statuses = {400, 401, 403, 405, 406, 409, 413, 414, 415, 422, 429}

    def __init__(
        self,
        spec: ExternalProductSpec,
        *,
        request_timeout: float = 30.0,
        smoke_max_attempts: int = 30,
        smoke_retry_delay: float = 0.25,
        transient_max_attempts: int = 12,
        transient_retry_delay: float = 1.0,
    ) -> None:
        self.spec = spec
        self.request_timeout = request_timeout
        self.smoke_max_attempts = max(1, int(smoke_max_attempts))
        self.smoke_retry_delay = max(0.0, float(smoke_retry_delay))
        self.transient_max_attempts = max(1, int(transient_max_attempts))
        self.transient_retry_delay = max(0.0, float(transient_retry_delay))
        parsed = urlsplit(spec.endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(
                f"{spec.key} endpoint must be an absolute http(s) URL"
            )
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                f"{spec.key} endpoint must not contain credentials, query, or fragment"
            )
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.base_path = parsed.path.rstrip("/")
        self.token = secrets.token_urlsafe(24)
        self.connection: HTTPConnection | HTTPSConnection | None = None
        self.status_counts: Counter[int] = Counter()
        self.mapping_counts: Counter[str] = Counter()
        self.fallback_counts: Counter[str] = Counter()
        self.started = False
        self.smoke_gate: dict[str, Any] = {}

    def _new_connection(self) -> HTTPConnection | HTTPSConnection:
        connection_type = HTTPSConnection if self.scheme == "https" else HTTPConnection
        return connection_type(
            self.host,
            self.port,
            timeout=self.request_timeout,
        )

    def start(self) -> None:
        """Require real allow/block proofs, allowing bounded engine warm-up.

        Adaptive WAF engines can need a few non-evaluation probes after a cold
        start.  At most ``smoke_max_attempts`` fixed SQLi probes are sent.  A
        second normal probe must still reach the proof backend, so reputation
        or broad source blocking cannot satisfy the gate.
        """

        saved_status = Counter(self.status_counts)
        saved_mapping = Counter(self.mapping_counts)
        saved_fallbacks = Counter(self.fallback_counts)
        self.started = True
        attack_attempts = 0
        attack_blocked = False
        try:
            normal_before = self.inspect(
                {
                    "payload": "product catalog item 2026",
                    "param_location": "query",
                    "param_name": "q",
                }
            )
            for attack_attempts in range(1, self.smoke_max_attempts + 1):
                attack = self.inspect(
                    {
                        "payload": "' UNION SELECT password FROM users--",
                        "param_location": "query",
                        "param_name": "q",
                    }
                )
                if attack.blocked:
                    attack_blocked = True
                    break
                if self.smoke_retry_delay:
                    time.sleep(self.smoke_retry_delay)
            normal_after = self.inspect(
                {
                    "payload": "ordinary account preference 79123",
                    "param_location": "query",
                    "param_name": "q",
                }
            )
        except Exception:
            self.close()
            raise
        self.status_counts = saved_status
        self.mapping_counts = saved_mapping
        self.fallback_counts = saved_fallbacks
        self.smoke_gate = {
            "status": "passed"
            if (
                not normal_before.blocked
                and normal_before.reached_backend
                and attack_blocked
                and not normal_after.blocked
                and normal_after.reached_backend
            )
            else "failed",
            "normal_checks": 2,
            "normal_before_status": normal_before.status_code,
            "normal_after_status": normal_after.status_code,
            "attack_attempts": attack_attempts,
            "max_attack_attempts": self.smoke_max_attempts,
            "bounded_warmup": attack_attempts > 1,
            "evaluation_records_used_for_warmup": 0,
        }
        if self.smoke_gate["status"] != "passed":
            self.close()
            raise RealWAFError(
                f"{self.spec.name} smoke gates failed: expected normal requests "
                "to reach the benchmark backend and SQLi to be blocked within "
                f"{self.smoke_max_attempts} bounded non-evaluation probes; "
                f"observed={self.smoke_gate}"
            )

    def inspect(self, record: dict) -> ProductDecision:
        if not self.started:
            raise RealWAFError(f"{self.spec.name} is not started")
        request = build_product_request(record, self.token)
        self.mapping_counts[request.carrier] += 1
        if request.fallback_reason:
            self.fallback_counts[request.fallback_reason] += 1
        target = f"{self.base_path}{request.target}" or "/"

        for attempt in range(self.transient_max_attempts):
            if self.connection is None:
                self.connection = self._new_connection()
            started = time.perf_counter()
            try:
                self.connection.request(
                    request.method,
                    target,
                    body=request.body,
                    headers=request.headers,
                )
                response = self.connection.getresponse()
                status = int(response.status)
                proof = response.getheader("X-WAD-Benchmark-Backend")
                reached_backend = 200 <= status < 400 and proof == "reached"
                if status in self.blocked_statuses and proof != "reached":
                    # Some products close a generated block page before its
                    # advertised chunk/body length.  The status and absence of
                    # the random backend proof are already a complete block
                    # decision, so do not let an unreadable cosmetic body turn
                    # a valid product decision into an infrastructure error.
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    self.status_counts[status] += 1
                    response.close()
                    self.connection.close()
                    self.connection = None
                    return ProductDecision(True, False, status, elapsed_ms)
                response.read()
                elapsed_ms = (time.perf_counter() - started) * 1000
                self.status_counts[status] += 1
                if reached_backend:
                    return ProductDecision(False, True, status, elapsed_ms)
                if (
                    500 <= status < 600
                    and attempt + 1 < self.transient_max_attempts
                ):
                    self.connection.close()
                    self.connection = None
                    if self.transient_retry_delay:
                        time.sleep(self.transient_retry_delay)
                    continue
                raise RealWAFError(
                    f"{self.spec.name} returned {status} without valid "
                    "backend proof or a recognized blocking status"
                )
            except (HTTPException, OSError, TimeoutError) as exc:
                if self.connection is not None:
                    self.connection.close()
                self.connection = None
                if attempt + 1 >= self.transient_max_attempts:
                    raise RealWAFError(
                        f"{self.spec.name} request failed "
                        f"{self.transient_max_attempts} times: "
                        f"carrier={request.carrier}, timeout={self.request_timeout}s, "
                        f"error={exc}"
                    ) from exc
                if self.transient_retry_delay:
                    time.sleep(self.transient_retry_delay)
        raise AssertionError("unreachable")

    def identity(self) -> dict[str, Any]:
        return {
            "key": self.spec.key,
            "name": self.spec.name,
            "version": self.spec.version,
            "implementation": "operator-managed real HTTP reverse-proxy execution",
            "is_actual_product_execution": True,
            "is_simulation": False,
            "endpoint_origin": f"{self.scheme}://{self.host}:{self.port}",
            "official_sources": [self.spec.project_url],
            "deployment_note": self.spec.deployment_note,
            "decision_policy": (
                "allowed only when the response carries the benchmark backend "
                "proof header; recognized 4xx without proof means product block"
            ),
            "smoke_gate": dict(self.smoke_gate),
        }

    def execution_summary(self) -> dict[str, Any]:
        return {
            "status_codes": {
                str(key): value for key, value in sorted(self.status_counts.items())
            },
            "request_carriers": dict(sorted(self.mapping_counts.items())),
            "fallbacks": dict(sorted(self.fallback_counts.items())),
        }

    def restore_execution_state(self, state: dict[str, Any]) -> None:
        self.status_counts = Counter(
            {
                int(key): int(value)
                for key, value in state.get("status_codes", {}).items()
            }
        )
        self.mapping_counts = Counter(
            {
                str(key): int(value)
                for key, value in state.get("request_carriers", {}).items()
            }
        )
        self.fallback_counts = Counter(
            {
                str(key): int(value)
                for key, value in state.get("fallbacks", {}).items()
            }
        )

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        self.started = False

    def __enter__(self) -> "ExternalReverseProxyWAF":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
