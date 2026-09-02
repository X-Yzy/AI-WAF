#!/usr/bin/env python3
"""Stable direct entry point for final delivery verification."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.verify_delivery_impl import main  # noqa: E402


if __name__ == "__main__":
    main()
