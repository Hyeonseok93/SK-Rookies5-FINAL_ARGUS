"""Diagnosis artifact paths under data/report/."""

from __future__ import annotations

from pathlib import Path

from diagnosis.context import DiagnosisContext


def section_report_dir(data_dir: Path, section_id: str) -> Path:
    return data_dir / "report" / section_id


def section_report_path(data_dir: Path, section_id: str) -> Path:
    return section_report_dir(data_dir, section_id) / "latest.yaml"


def section_evidence_dir(data_dir: Path, section_id: str) -> Path:
    return section_report_dir(data_dir, section_id) / "evidence"


def resolve_report_path(
    *,
    ctx: DiagnosisContext | None,
    section_id: str,
    module_dir: Path | None = None,
) -> Path:
    """Runtime report at data/report/{id}/latest.yaml."""
    del module_dir
    data_dir = ctx.data_dir if ctx is not None else Path(__file__).resolve().parents[1] / "data"
    return section_report_path(data_dir, section_id)


# Back-compat aliases (tests / external callers)
diagnosis_report_dir = section_report_dir
diagnosis_report_path = section_report_path
