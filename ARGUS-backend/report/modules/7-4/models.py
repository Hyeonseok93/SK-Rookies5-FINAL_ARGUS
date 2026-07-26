"""Normalized models for the 7-4 final report."""

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
    case_id: str
    case_type: str
    title: str
    severity: str
    finding_type: str
    target: str
    test_method: str
    assessment: str
    remediation: list[str]
    guideline_reference: str
    facts: list[tuple[str, str]] = field(default_factory=list)
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
    dependency_file_required: str
    findings: list[FindingReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

