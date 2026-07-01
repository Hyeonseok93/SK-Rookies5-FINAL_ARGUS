"""Base diagnosis module contract and stub implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

import yaml

from diagnosis.context import DiagnosisContext
from diagnosis.result import SectionReport, utc_now_iso


class DiagnosisModule(ABC):
    section_id: str
    title: str
    chapter: int
    implemented: bool = False
    diagnosable: bool = True
    review_later: bool = False
    status_label: str | None = None
    engine: str = "pending"
    module_dir: Path

    def report_path(self) -> Path:
        return self.module_dir / "reports" / "latest.yaml"

    def load_report(self, ctx: DiagnosisContext) -> SectionReport | None:
        path = self.report_path()
        if not path.is_file():
            return None
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return None
        return SectionReport.from_dict(raw)

    @abstractmethod
    def run(self, ctx: DiagnosisContext) -> SectionReport:
        """Execute diagnosis for this guideline section."""

    def save_report(self, ctx: DiagnosisContext, report: SectionReport) -> Path:
        path = self.report_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(report.to_dict(), allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        return path


class StubDiagnosisModule(DiagnosisModule):
    """Placeholder module — registry shell until real logic is added."""

    def __init__(
        self,
        *,
        section_id: str,
        title: str,
        chapter: int,
        module_dir: Path,
        implemented: bool = False,
        diagnosable: bool = True,
        review_later: bool = False,
        status_label: str | None = None,
        engine: str = "pending",
    ) -> None:
        self.section_id = section_id
        self.title = title
        self.chapter = chapter
        self.module_dir = module_dir
        self.implemented = implemented
        self.diagnosable = diagnosable
        self.review_later = review_later
        self.status_label = status_label
        self.engine = engine

    @classmethod
    def from_manifest(cls, manifest_path: Path) -> StubDiagnosisModule:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"Invalid manifest: {manifest_path}")
        return cls(
            section_id=str(raw["id"]),
            title=str(raw.get("title", "")),
            chapter=int(raw.get("chapter", 0)),
            module_dir=manifest_path.parent,
            implemented=bool(raw.get("implemented", False)),
            diagnosable=bool(raw.get("diagnosable", True)),
            review_later=bool(raw.get("review_later", False)),
            status_label=str(raw["status_label"]).strip()
            if raw.get("status_label")
            else None,
            engine=str(raw.get("engine", "pending")),
        )

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        if not self.diagnosable:
            if self.review_later:
                msg = "추후 검토 항목"
            elif self.status_label:
                msg = self.status_label
            else:
                msg = "추후 검토 항목"
            report = SectionReport(
                section_id=self.section_id,
                title=self.title,
                chapter=self.chapter,
                status="not_diagnosable",
                implemented=False,
                message=msg,
                checked_at=utc_now_iso(),
            )
            self.save_report(ctx, report)
            return report

        report = SectionReport(
            section_id=self.section_id,
            title=self.title,
            chapter=self.chapter,
            status="not_implemented" if not self.implemented else "pending",
            implemented=self.implemented,
            message="모듈 껍데기 — 진단 로직 미구현",
            checked_at=utc_now_iso(),
        )
        self.save_report(ctx, report)
        return report


def load_module_from_manifest(module_dir: Path) -> DiagnosisModule:
    manifest = module_dir / "manifest.yaml"
    if not manifest.is_file():
        raise FileNotFoundError(f"Missing manifest: {manifest}")
    return StubDiagnosisModule.from_manifest(manifest)
