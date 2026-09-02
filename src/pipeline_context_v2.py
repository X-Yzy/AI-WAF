"""Final public pipeline API."""

from __future__ import annotations

import re

from .pipeline_context_v1 import DetectionPipeline as _ContextPipeline
from .pipeline_core import DetectionResult


class DetectionPipeline(_ContextPipeline):
    """Use ASCII token boundaries inside multilingual discussions."""

    _TECHNICAL_TERM = re.compile(
        r"(?<![A-Za-z0-9_])(?:select|join|union|insert|update|delete|where|"
        r"script|iframe|onload|onerror|curl|wget|base64|jwt|sleep|benchmark|"
        r"sql|xss|csrf|xxe|ssti)(?![A-Za-z0-9_])",
        re.IGNORECASE,
    )
