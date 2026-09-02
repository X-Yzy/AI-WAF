"""Local Web attack detection experiment workbench.

This module intentionally reuses the full original local dashboard application
defined in :mod:`src.app`.  The generated dashboard excludes the server-only
live-protection page and adds batch inference.  Server deployment continues to
use :mod:`src.runtime_api` and the reverse-proxy/operations modules.
"""

from .app import app


__all__ = ["app"]
