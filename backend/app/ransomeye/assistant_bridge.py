"""Thin public re-export of assistant.py's LLM call plumbing, so copilot.py
(and anything else in this package) reuses the exact same HTTP/provider code
the alert correlation engine's incident assistant (app/assistant.py) uses,
instead of duplicating it.
"""

from __future__ import annotations

from ..assistant import _call_chat_api as call_chat_api
from ..assistant import _configured_providers as configured_providers

__all__ = ["call_chat_api", "configured_providers"]
