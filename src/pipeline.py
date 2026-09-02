"""Final public pipeline API."""

from __future__ import annotations

import re

from .pipeline_context_v3 import DetectionPipeline as _DocumentedPipeline
from .pipeline_core import DetectionResult


class DetectionPipeline(_DocumentedPipeline):
    """Final precision fixes for documented markup and format strings."""

    def __init__(self):
        super().__init__()
        # ``%40n`` in an URL is the encoded ``@`` followed by a hostname
        # beginning with n, not automatically a printf write. Keep the
        # unambiguous %n and positional %1$n forms as high-confidence rules;
        # ambiguous width syntax continues to the statistical models.
        for ruleset in self.rule_engine.rulesets.values():
            for rule in ruleset.rules:
                if rule.id == "format_write":
                    rule.pattern = r"%(?:n|[1-9][0-9]*\$n)"
                    rule._compiled = re.compile(rule.pattern, re.IGNORECASE)

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
        if documented and entity_escaped:
            return True
        return super()._safe_context(payload, restored, location, name)
