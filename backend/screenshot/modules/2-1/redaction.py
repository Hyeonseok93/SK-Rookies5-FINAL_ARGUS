"""Mask secrets before rendering evidence."""

from __future__ import annotations

import re

_SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_JSON_SECRET_RE = re.compile(
    r'(?i)("(?:password|passwordConfirm|accessToken|refreshToken|token)"\s*:\s*")[^"]*(")'
)
# Presigned/signed storage URLs (S3, GCS, Azure) leak usable credentials in
# the query string itself, not just in JSON body fields or auth headers.
_SIGNED_URL_PARAM_RE = re.compile(
    r"(?i)([?&](?:x-amz-signature|x-amz-credential|x-amz-security-token"
    r"|x-goog-signature|signature|sig|token|access_token)=)[^&\s\"']+"
)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: (
            "***REDACTED***"
            if key.lower() in _SECRET_HEADERS
            else _SIGNED_URL_PARAM_RE.sub(r"\1***REDACTED***", value or "")
        )
        for key, value in headers.items()
    }


def redact_text(value: str) -> str:
    redacted = _BEARER_RE.sub(r"\1***REDACTED***", value or "")
    redacted = _JSON_SECRET_RE.sub(r"\1***REDACTED***\2", redacted)
    return _SIGNED_URL_PARAM_RE.sub(r"\1***REDACTED***", redacted)
