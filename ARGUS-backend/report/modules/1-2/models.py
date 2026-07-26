"""Data models used by the 1-2 report builder and renderer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class EvidenceImage:
    kind: str
    caption: str
    source_path: str
    data_uri: str


@dataclass(slots=True)
class FindingReport:
    finding_id: str
    title: str
    severity: str
    injection_type: str
    method: str
    url: str
    parameter: str
    payload: str
    verification_type: str
    verification_status: str
    confidence: str
    detection_method: str
    assessment: str
    remediation: list[str]
    guideline_reference: str
    observations: list[str] = field(default_factory=list)
    images: list[EvidenceImage] = field(default_factory=list)


@dataclass(slots=True)
class ReportDocument:
    section_id: str
    title: str
    status: str
    checked_at: str
    generated_at: str
    report_id: str
    source_report: str
    findings: list[FindingReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
