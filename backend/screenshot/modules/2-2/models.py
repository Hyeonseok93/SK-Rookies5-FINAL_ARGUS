"""Shared data models for 2-2 evidence screenshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HttpExchange:
    method: str
    url: str
    display_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_body_raw: bytes = b""
    elapsed_ms: float | None = None


@dataclass(slots=True)
class EvidenceCase:
    finding_id: str
    section_id: str
    title: str
    rule_id: str
    parameter: str
    payload: str
    trigger: str
    baseline: HttpExchange
    attack: HttpExchange
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CaptureArtifact:
    kind: str
    path: str
