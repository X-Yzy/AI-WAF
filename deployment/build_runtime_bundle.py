#!/usr/bin/env python3
"""Build the independent minimal server bundle with compatible public API."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from deployment import build_runtime_bundle_core as core  # noqa: E402
from deployment.build_runtime_bundle_core import *  # noqa: F401,F403,E402


_validate = core._validate

for required in (
    "pipeline_core.py",
    "pipeline_context_v1.py",
    "pipeline_context_v2.py",
    "pipeline_context_v3.py",
):
    if required not in core.RUNTIME_MODULES:
        modules = list(core.RUNTIME_MODULES)
        modules.insert(modules.index("pipeline.py"), required)
        core.RUNTIME_MODULES = tuple(modules)


if __name__ == "__main__":
    core.main()
