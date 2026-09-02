"""Bounded, thread-safe HTTP scanner behaviour detector.

User-Agent is deliberately weak evidence.  A client is considered scanner-like
only when it combines request velocity/path diversity with known probe routes or
multiple attack-shaped targets.  State is in-memory, TTL-bounded and contains no
query values beyond boolean signal extraction.
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


SCANNER_UA = re.compile(
    r"(?:\bnuclei\b|\bsqlmap\b|nikto|\bffuf\b|gobuster|dirsearch|\bzap/|wapiti|arachni|dirbuster|w3af)",
    re.IGNORECASE,
)
KNOWN_PROBE = re.compile(
    r"(?:^/\.env(?:$|[/.])|^/\.git/(?:config|head)|^/server-status$|^/phpinfo\.php$|"
    r"^/actuator/(?:env|heapdump|jolokia)|/vendor/phpunit/.*/eval-stdin\.php$|"
    r"^/wp-admin/setup-config\.php$|^/cgi-bin/(?:status|test-cgi)|^/\.aws/credentials$)",
    re.IGNORECASE,
)
ATTACK_TARGET = re.compile(
    r"(?:\.\.[/\\]|%2e%2e|\bunion(?:%20|\s)+(?:all(?:%20|\s)+)?select\b|"
    r"(?:%3c|<)(?:svg|script)|169\.254\.169\.254|(?:%27|['\"])\s*(?:or|and)(?:%20|\s)+\d)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScannerDecision:
    verdict: bool
    score: int
    signals: tuple[str, ...]
    requests_in_window: int
    distinct_paths: int
    probe_count: int
    attack_target_count: int


class ScannerBehaviorDetector:
    def __init__(self, window_seconds: float = 15.0, max_clients: int = 10000) -> None:
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._events: dict[str, deque[tuple[float, str, bool, bool]]] = defaultdict(deque)
        self._last_seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def observe(self, client_id: str, target: str, user_agent: str = "",
                now: float | None = None) -> ScannerDecision:
        timestamp = time.monotonic() if now is None else float(now)
        parts = urlsplit(target)
        path = unquote(parts.path or "/").lower()
        searchable = unquote(target)
        known_probe = bool(KNOWN_PROBE.search(path))
        attack_target = bool(ATTACK_TARGET.search(searchable))
        ua_signal = bool(SCANNER_UA.search(user_agent or ""))

        with self._lock:
            events = self._events[client_id]
            events.append((timestamp, path, known_probe, attack_target))
            cutoff = timestamp - self.window_seconds
            while events and events[0][0] < cutoff:
                events.popleft()
            self._last_seen[client_id] = timestamp
            if len(self._events) > self.max_clients:
                for stale_client, _ in sorted(self._last_seen.items(), key=lambda item: item[1])[:max(1, self.max_clients // 10)]:
                    self._events.pop(stale_client, None)
                    self._last_seen.pop(stale_client, None)
            snapshot = tuple(events)

        request_count = len(snapshot)
        distinct_paths = len({item[1] for item in snapshot})
        probe_count = sum(item[2] for item in snapshot)
        attack_count = sum(item[3] for item in snapshot)
        signals: list[str] = []
        score = 0
        if ua_signal:
            score += 1
            signals.append("scanner_user_agent")
        if distinct_paths >= 8 and request_count >= 8:
            score += 2
            signals.append("rapid_path_diversity")
        if request_count >= 25:
            score += 1
            signals.append("high_request_rate")
        if probe_count >= 2:
            score += 4
            signals.append("multiple_known_probe_routes")
        elif probe_count == 1:
            score += 1
            signals.append("known_probe_route")
        if attack_count >= 2:
            score += 3
            signals.append("multiple_attack_shaped_targets")
        elif attack_count == 1:
            score += 1
            signals.append("attack_shaped_target")
        return ScannerDecision(
            verdict=score >= 4, score=score, signals=tuple(signals),
            requests_in_window=request_count, distinct_paths=distinct_paths,
            probe_count=probe_count, attack_target_count=attack_count,
        )

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._last_seen.clear()
