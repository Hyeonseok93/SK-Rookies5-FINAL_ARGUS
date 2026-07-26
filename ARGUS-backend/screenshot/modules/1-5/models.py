"""Models for 1-5 (unvalidated redirect/forward) evidence capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RedirectCase:
    case_id: str
    rule_id: str
    title: str
    severity: str
    target_url: str
    display_url: str
    method: str
    param_name: str
    payload: str
    status_line: str
    detail_lines: list[str] = field(default_factory=list)
    description: str = ""
    recommendation: str = ""


@dataclass(slots=True)
class CaptureArtifact:
    kind: str
    path: str
