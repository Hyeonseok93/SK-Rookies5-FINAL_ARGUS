"""Mask secrets before rendering 1-1 evidence text blocks."""

from __future__ import annotations

import re

_SECRET_HEADER_NAMES = r"authorization|cookie|set-cookie|x-api-key"
_HEADER_LINE_RE = re.compile(
    rf'(?i)("(?:{_SECRET_HEADER_NAMES})"\s*:\s*")[^"]*(")'
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_JSON_SECRET_RE = re.compile(
    r'(?i)("(?:password|passwordConfirm|accessToken|refreshToken|token)"\s*:\s*")[^"]*(")'
)


def redact_text(value: str) -> str:
    """Mask Authorization/Cookie header values and password/token JSON fields."""
    redacted = _HEADER_LINE_RE.sub(r"\1***REDACTED***\2", value or "")
    redacted = _BEARER_RE.sub(r"\1***REDACTED***", redacted)
    return _JSON_SECRET_RE.sub(r"\1***REDACTED***\2", redacted)
