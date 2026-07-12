"""Recover structured pieces from the 1-1 scanner's pre-formatted request text.

The scanner always renders requests as::

    {METHOD} {URL}

    Headers:
    {...}

    Body:
    {body}

(see ``diagnosis/modules/1-1/scanner.py:_format_request`` and
``diagnosis/modules/1-1/zap_runner.py:format_http_request``). The header
block is not valid JSON (no separating commas) so it is not parsed here;
only the body, which is everything after the final ``"\\n\\nBody:\\n"``
separator, is recovered.
"""

from __future__ import annotations

_BODY_SEPARATOR = "\n\nBody:\n"


def extract_body(request_text: str) -> str:
    text = request_text or ""
    if _BODY_SEPARATOR not in text:
        return ""
    return text.split(_BODY_SEPARATOR, 1)[1]


def extract_content_type(request_text: str) -> str:
    """Best-effort Content-Type lookup from the Headers: block, needed to
    replay a forged CSRF body with the same header the original request used."""
    for line in (request_text or "").splitlines():
        if line.strip().lower().startswith('"content-type"'):
            return line.split(":", 1)[-1].strip().strip('",')
    return ""
