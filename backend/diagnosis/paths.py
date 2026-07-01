"""Diagnosis artifact paths under data/diagnosis/."""

from __future__ import annotations

from pathlib import Path

from diagnosis.context import DiagnosisContext


def diagnosis_report_dir(data_dir: Path, section_id: str) -> Path:
    return data_dir / "diagnosis" / section_id


def diagnosis_report_path(data_dir: Path, section_id: str) -> Path:
    return diagnosis_report_dir(data_dir, section_id) / "latest.yaml"


def legacy_module_report_path(module_dir: Path) -> Path:
    return module_dir / "reports" / "latest.yaml"


def resolve_report_path(
    *,
    ctx: DiagnosisContext | None,
    section_id: str,
    module_dir: Path,
) -> Path:
    """Prefer data/diagnosis/{id}/latest.yaml; fall back to module reports/."""
    if ctx is not None:
        runtime = diagnosis_report_path(ctx.data_dir, section_id)
        if runtime.is_file():
            return runtime
    legacy = legacy_module_report_path(module_dir)
    if legacy.is_file():
        return legacy
    if ctx is not None:
        return diagnosis_report_path(ctx.data_dir, section_id)
    return legacy
