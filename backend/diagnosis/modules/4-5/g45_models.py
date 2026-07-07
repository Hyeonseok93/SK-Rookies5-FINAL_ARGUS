from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diagnosis.result import DiagnosisFinding

@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""
