"""Production operations dashboard backed by the shared proxy runtime files."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import hmac
import json
import os
from pathlib import Path
from statistics import mean

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from .settings import RUNTIME_ROOT


_security = HTTPBasic(auto_error=False)
_dashboard_asset = Path(__file__).with_name("ops_dashboard.html")


def _authorize(credentials: HTTPBasicCredentials | None = Depends(_security)) -> None:
    expected_password = os.environ.get("WAD_DASHBOARD_PASSWORD", "")
    if not expected_password:
        return
    expected_username = os.environ.get("WAD_DASHBOARD_USERNAME", "admin")
    username = credentials.username if credentials else ""
    password = credentials.password if credentials else ""
    if not (
        hmac.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8"))
        and hmac.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Dashboard authentication required",
            headers={"WWW-Authenticate": 'Basic realm="AI-WAF Operations"'},
        )


def _authorize_control(
    credentials: HTTPBasicCredentials | None = Depends(_security),
) -> None:
    if not os.environ.get("WAD_DASHBOARD_PASSWORD", ""):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Set WAD_DASHBOARD_PASSWORD before enabling runtime controls",
        )
    _authorize(credentials)


# Shared dependency for every endpoint that mutates runtime state.
require_control_auth = _authorize_control


class ProxyControlRequest(BaseModel):
    mode: str = Field(pattern="^(monitor|block)$")
    fail_policy: str = Field(pattern="^(open|closed)$")


class RuntimeMonitor:
    """Read and aggregate bounded tails of proxy runtime files."""

    def __init__(self, runtime_root: Path | None = None) -> None:
        root = runtime_root or RUNTIME_ROOT
        self.log_path = Path(
            os.environ.get("WAD_PROXY_LOG_FILE", str(root / "proxy_access.jsonl"))
        )
        self.status_path = self.log_path.with_name("proxy_status.json")

    @staticmethod
    def _read_json(path: Path) -> dict:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _parse_timestamp(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None

    def tail(self, max_records: int = 20_000, max_bytes: int = 16 * 1024 * 1024) -> list[dict]:
        if not self.log_path.is_file():
            return []
        try:
            with self.log_path.open("rb") as handle:
                size = handle.seek(0, os.SEEK_END)
                offset = max(0, size - max_bytes)
                handle.seek(offset)
                chunk = handle.read(max_bytes)
            if offset:
                chunk = chunk.split(b"\n", 1)[-1]
            rows: list[dict] = []
            for raw in chunk.splitlines()[-max_records:]:
                try:
                    value = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(value, dict):
                    rows.append(value)
            return rows
        except OSError:
            return []

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        index = round((len(ordered) - 1) * percentile)
        return round(ordered[index], 3)

    @staticmethod
    def _event_threat_names(row: dict) -> list[str]:
        names: list[str] = []
        for threat in row.get("threats", []):
            if not isinstance(threat, dict):
                continue
            hits = threat.get("rule_hits") or []
            if hits:
                names.extend(str(hit) for hit in hits[:3])
            else:
                names.append(str(threat.get("name") or threat.get("layer") or "model_detected"))
        return names

    def overview(self, hours: int = 24, event_limit: int = 100) -> dict:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=hours)
        rows = []
        for row in self.tail():
            timestamp = self._parse_timestamp(row.get("timestamp"))
            if timestamp is not None and timestamp >= cutoff:
                rows.append(row)

        outcomes = Counter(str(row.get("outcome", "unknown")) for row in rows)
        methods = Counter(str(row.get("method", "UNKNOWN")) for row in rows)
        threats = Counter(
            name for row in rows for name in self._event_threat_names(row)
        )
        attack_count = sum(int(row.get("threat_count", 0) or 0) > 0 for row in rows)
        detection_latencies = []
        for row in rows:
            value = row.get("detection_elapsed_ms")
            if value is None:
                continue
            try:
                detection_latencies.append(float(value))
            except (TypeError, ValueError):
                continue

        bucket_minutes = 5 if hours <= 6 else (30 if hours <= 24 else 120)
        buckets: dict[datetime, dict[str, int]] = {}
        for row in rows:
            timestamp = self._parse_timestamp(row.get("timestamp"))
            if timestamp is None:
                continue
            minute = timestamp.minute - timestamp.minute % bucket_minutes
            bucket = timestamp.replace(minute=minute, second=0, microsecond=0)
            if bucket_minutes >= 60:
                hour_step = bucket_minutes // 60
                bucket = bucket.replace(hour=bucket.hour - bucket.hour % hour_step, minute=0)
            item = buckets.setdefault(bucket, {"requests": 0, "attacks": 0, "blocked": 0})
            item["requests"] += 1
            item["attacks"] += int(row.get("threat_count", 0) or 0) > 0
            item["blocked"] += row.get("outcome") == "blocked"

        proxy_status = self._read_json(self.status_path)
        proxy_control = self._read_json(
            self.log_path.with_name("proxy_control.json")
        )
        heartbeat = self._parse_timestamp(proxy_status.get("timestamp"))
        heartbeat_age = (now - heartbeat).total_seconds() if heartbeat else None
        if heartbeat_age is not None and heartbeat_age <= 90:
            runtime_status = "online"
        elif proxy_status:
            runtime_status = "stale"
        elif self.log_path.is_file():
            runtime_status = "waiting"
        else:
            runtime_status = "not_configured"

        latest = rows[-1] if rows else {}
        errors = outcomes.get("backend_error", 0) + outcomes.get("error", 0)
        summary = {
            "requests": len(rows),
            "attacks": attack_count,
            "blocked": outcomes.get("blocked", 0),
            "errors": errors,
            "attack_rate": round(attack_count / max(len(rows), 1) * 100, 2),
            "avg_detection_latency_ms": (
                round(mean(detection_latencies), 3)
                if detection_latencies else 0
            ),
            "p95_detection_latency_ms": self._percentile(
                detection_latencies, 0.95
            ),
        }
        return {
            "status": runtime_status,
            "mode": proxy_control.get("mode") or proxy_status.get("mode") or latest.get("mode") or os.environ.get("WAD_PROXY_MODE", "unknown"),
            "fail_policy": proxy_control.get("fail_policy") or proxy_status.get("fail_policy") or os.environ.get("WAD_PROXY_FAIL_POLICY", "unknown"),
            "backend": proxy_status.get("backend") or os.environ.get("WAD_PROXY_BACKEND", "unknown"),
            "heartbeat_at": proxy_status.get("timestamp"),
            "last_event_at": latest.get("timestamp"),
            "log_file": str(self.log_path),
            "window_hours": hours,
            "window_records": len(rows),
            "summary": summary,
            "by_outcome": dict(outcomes.most_common()),
            "by_method": dict(methods.most_common()),
            "by_threat": dict(threats.most_common(12)),
            "timeline": [
                {"timestamp": key.isoformat(), **value}
                for key, value in sorted(buckets.items())
            ],
            "records": list(reversed(rows[-event_limit:])),
        }

    def write_control(self, mode: str, fail_policy: str) -> dict:
        control_path = self.log_path.with_name("proxy_control.json")
        temporary = control_path.with_name(f".{control_path.name}.{os.getpid()}.tmp")
        value = {
            "mode": mode,
            "fail_policy": fail_policy,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        control_path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        os.replace(temporary, control_path)
        return value


def create_ops_router() -> APIRouter:
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard(_: None = Depends(_authorize)):
        if not _dashboard_asset.is_file():
            raise HTTPException(status_code=503, detail="Dashboard asset is missing")
        return HTMLResponse(
            _dashboard_asset.read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/ops/api/overview", tags=["operations"])
    def operations_overview(
        hours: int = Query(default=24, ge=1, le=168),
        limit: int = Query(default=100, ge=10, le=500),
        _: None = Depends(_authorize),
    ):
        return RuntimeMonitor().overview(hours=hours, event_limit=limit)

    @router.post("/ops/api/proxy/control", tags=["operations"])
    def update_proxy_control(
        request: ProxyControlRequest,
        _: None = Depends(_authorize_control),
    ):
        return RuntimeMonitor().write_control(request.mode, request.fail_policy)

    return router
