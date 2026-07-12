"""Shared data models for 1-1 (Stored XSS / CSRF) evidence screenshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HttpExchange:
    """A single request/response pair as recorded by the 1-1 scanner.

    ``request_text``/``response_text`` are the scanner's pre-formatted
    "METHOD URL\\n\\nHeaders:\\n{...}\\n\\nBody:\\n{body}" blocks (see
    ``scanner.py:_format_request`` / ``zap_runner.py:format_http_request``).
    They are kept as opaque text rather than parsed into header dicts because
    the header block is not valid JSON (no separating commas).
    """

    method: str
    url: str
    display_url: str = ""
    status_code: int | None = None
    request_text: str = ""
    response_text: str = ""
    elapsed_ms: float | None = None


@dataclass(slots=True)
class AttackerSubmission:
    """Result of live-replaying a CSRF finding from a simulated attacker page."""

    target_url: str
    method: str
    request_body: str
    status_code: int | None = None
    response_text: str = ""
    elapsed_ms: float | None = None


@dataclass(slots=True)
class EvidenceCase:
    finding_id: str
    section_id: str
    vuln_type: str  # "Stored XSS" | "CSRF"
    title: str
    parameter: str
    payload: str
    validation_status: str
    confidence: str
    account_role: str
    exchange: HttpExchange
    attacker_submission: AttackerSubmission | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CaptureArtifact:
    kind: str
    path: str
