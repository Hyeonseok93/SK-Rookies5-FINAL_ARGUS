"""Diagnosis result models (section report, findings)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class DiagnosisFinding:
    severity: str = "info"
    message: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SectionReport:
    section_id: str
    title: str
    chapter: int
    status: str = "pending"
    implemented: bool = False
    findings: list[DiagnosisFinding] = field(default_factory=list)
    message: str = ""
    checked_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "title": self.title,
            "chapter": self.chapter,
            "status": self.status,
            "implemented": self.implemented,
            "findings": [f.to_dict() for f in self.findings],
            "message": self.message,
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SectionReport:
        findings = [
            DiagnosisFinding(
                severity=str(f.get("severity", "info")),
                message=str(f.get("message", "")),
                evidence=dict(f.get("evidence") or {}),
            )
            for f in raw.get("findings") or []
        ]
        return cls(
            section_id=str(raw.get("section_id", "")),
            title=str(raw.get("title", "")),
            chapter=int(raw.get("chapter", 0)),
            status=str(raw.get("status", "pending")),
            implemented=bool(raw.get("implemented", False)),
            findings=findings,
            message=str(raw.get("message", "")),
            checked_at=raw.get("checked_at"),
        )


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()
