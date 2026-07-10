"""Light masking for 2-2 evidence boards.

Auth tokens (Bearer / Cookie / accessToken) are kept visible so request
evidence matches what was actually sent. Only password-like body fields
are masked.
"""

from __future__ import annotations

import re

_PASSWORD_JSON_RE = re.compile(
    r'(?i)("(?:password|passwordConfirm|newPassword|newPasswordConfirm|pw)"\s*:\s*")[^"]*(")'
)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Pass auth headers through unchanged for evidence screenshots."""
    return {str(key): str(value) for key, value in (headers or {}).items()}


def redact_text(value: str) -> str:
    """Keep tokens visible; mask password fields in JSON bodies only."""
    return _PASSWORD_JSON_RE.sub(r"\1***\2", value or "")
