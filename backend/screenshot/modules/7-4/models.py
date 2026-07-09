"""Models for 7-4 evidence capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class WebConfigCase:
    case_id: str
    target_url: str
    display_url: str
    severity: str
    status_code: int | None
    response_headers: dict[str, str]
    response_body: str
    issues: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ScaCase:
    case_id: str
    component: str
    version: str
    severity: str
    advisory_id: str
    advisory_url: str
    advisory_summary: str
    remediation: str
    cve_id: str = ""
    cvss_version: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    epss: float = 0.0
    remote: bool = False
    unauthenticated: bool = False
    public_poc: bool = False
    operating_conditions: str = "unconfirmed"
    cvss_prerequisites: str = "not available"
    vulnerable_range: str = ""
    representative_patched_version: str = ""
    recommended_version: str = ""
    selection_reason: str = ""
    cve_ids: list[str] = field(default_factory=list)
    dependency_lines: list[str] = field(default_factory=list)
    canvas_url: str = ""
