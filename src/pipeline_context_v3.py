"""Final public pipeline API."""

from __future__ import annotations

from .pipeline_context_v2 import DetectionPipeline as _MultilingualPipeline
from .pipeline_core import DetectionResult


class DetectionPipeline(_MultilingualPipeline):
    """Recognize explicitly labelled, entity-escaped markup documentation."""

    @classmethod
    def _safe_context(
        cls, payload: str, restored: str, location: str, name: str
    ) -> bool:
        lower = payload.lower()
        documented = any(
            marker in lower
            for marker in (
                "教程", "文档", "示例", "tutorial", "documentation", "example"
            )
        )
        entity_escaped = (
            ("&lt;" in lower or "&#60;" in lower)
            and "<" not in payload
            and ">" not in payload
        )
        if location in {"body", "query"} and documented and entity_escaped:
            return True
        return super()._safe_context(payload, restored, location, name)
