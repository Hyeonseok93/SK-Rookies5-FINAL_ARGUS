"""Mask secrets before rendering evidence."""

from __future__ import annotations

import re

_SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_JSON_SECRET_RE = re.compile(
    r'(?i)("(?:password|passwordConfirm|accessToken|refreshToken|token)"\s*:\s*")[^"]*(")'
)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: ("***REDACTED***" if key.lower() in _SECRET_HEADERS else value)
        for key, value in headers.items()
    }


def redact_text(value: str) -> str:
    redacted = _BEARER_RE.sub(r"\1***REDACTED***", value or "")
    return _JSON_SECRET_RE.sub(r"\1***REDACTED***\2", redacted)
