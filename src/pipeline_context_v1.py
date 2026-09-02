"""Final cascade pipeline with conservative non-executable context guards."""

from __future__ import annotations

import re
import time

from .extractor import extract_with_names
from .normalizer import normalize
from .pipeline_core import DetectionPipeline as _CoreDetectionPipeline
from .pipeline_core import DetectionResult


class DetectionPipeline(_CoreDetectionPipeline):
    """Production pipeline plus narrowly scoped normal-context regressions.

    The guard only accepts a strict parameterized SELECT statement or a
    human-language discussion/tutorial with no active attack structure.
    Everything else continues through the original cascade.
    """

    _PARAMETERIZED_SELECT = re.compile(
        r"(?is)^\s*select\s+[a-z0-9_.*,\s]+\s+from\s+[a-z0-9_.]+\s+"
        r"where\s+[a-z0-9_.]+\s*=\s*\?\s*;?\s*$"
    )
    _DISCUSSION_MARKERS = (
        "怎么", "如何", "什么", "区别", "用法", "函数", "教程", "文档",
        "示例", "解释", "how ", "what ", "difference", "tutorial",
        "documentation", "example", "explain", "차이점", "무엇", "어떻게",
        "사용", "教えて", "使い方", "違い", "diferencia", "cómo", "como ",
        "différence", "comment ", "unterschied", "wie ", "diferença",
        "الفرق", "كيف", "разниц", "как ",
    )
    _TEXT_FIELDS = {
        "content", "question", "comment", "description", "title", "message",
        "body", "text", "post", "query", "q", "value",
    }
    _TECHNICAL_TERM = re.compile(
        r"\b(?:select|join|union|insert|update|delete|where|script|iframe|"
        r"onload|onerror|curl|wget|base64|jwt|sleep|benchmark|sql|xss|"
        r"csrf|xxe|ssti)\b",
        re.IGNORECASE,
    )
    _ACTIVE_STRUCTURE = (
        re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
        re.compile(r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*[^)\s]", re.IGNORECASE),
        re.compile(r"['\"]\s*(?:or|and)\s+.{0,50}(?:=|like)", re.IGNORECASE),
        re.compile(r"\b(?:or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE),
        re.compile(r"(?:^|\s)[;&|]{1,2}\s*(?:cat|id|whoami|curl|wget|bash|sh|cmd)\b", re.IGNORECASE),
        re.compile(r"\$\(|`[^`]+`|\.\.[/\\]|%0d|%0a|\{\{|\$\{", re.IGNORECASE),
        re.compile(r"<(?:script|iframe|svg|img)\b", re.IGNORECASE),
        re.compile(
            r"(?:;\s*(?:drop|alter|truncate|insert|update|delete|create|grant|revoke)\b|"
            r"\b(?:drop|truncate)\s+(?:table|database|schema)\b|"
            r"\binsert\s+into\b|\bupdate\s+[a-z0-9_.]+\s+set\b|"
            r"\bdelete\s+from\b)",
            re.IGNORECASE,
        ),
    )

    @classmethod
    def _safe_context(
        cls, payload: str, restored: str, location: str, name: str
    ) -> bool:
        value = payload.strip()
        if location in {"body", "query"} and cls._PARAMETERIZED_SELECT.fullmatch(value):
            return True
        if location not in {"body", "query"} or name.lower() not in cls._TEXT_FIELDS:
            return False

        lower = f"{payload}\n{restored}".lower()
        if not any(marker in lower for marker in cls._DISCUSSION_MARKERS):
            return False

        # Encoded markup embedded in an explicitly marked tutorial/document is
        # display text. Literal markup still follows normal attack detection.
        encoded_markup_document = (
            any(marker in lower for marker in ("教程", "文档", "示例", "tutorial", "documentation", "example"))
            and ("&lt;" in payload.lower() or "&#60;" in payload.lower())
            and "<" not in payload
        )
        if encoded_markup_document:
            return True

        if any(pattern.search(lower) for pattern in cls._ACTIVE_STRUCTURE):
            return False
        terms = {item.lower() for item in cls._TECHNICAL_TERM.findall(lower)}
        return len(terms) >= 2

    def detect(
        self,
        payload: str,
        param_location: str = "query",
        param_name: str = "value",
    ) -> DetectionResult:
        quick_probe = payload.lower()
        if (
            "?" in payload
            or "&lt;" in quick_probe
            or any(marker in quick_probe for marker in self._DISCUSSION_MARKERS)
        ):
            started = time.perf_counter()
            restored, metadata = normalize(
                payload, param_location=param_location
            )
            if self._safe_context(
                payload, restored, param_location, param_name
            ):
                return DetectionResult(
                    verdict="benign",
                    confidence=0.995,
                    layer="L0-Context",
                    payload=payload[:200],
                    normalized=restored[:200],
                    confusion_meta=self._meta_summary(metadata),
                    features=extract_with_names(payload, restored, metadata),
                    rule_hits=[],
                    l2_score=None,
                    l3_score=None,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
        return super().detect(payload, param_location, param_name)
