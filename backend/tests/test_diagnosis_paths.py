"""Tests for diagnosis report path resolution."""

from __future__ import annotations

from pathlib import Path

from diagnosis.context import DiagnosisContext
from diagnosis.paths import diagnosis_report_path, resolve_report_path


def test_resolve_report_path_prefers_runtime(tmp_path: Path):
    module_dir = tmp_path / "modules" / "1-1"
    legacy = module_dir / "reports" / "latest.yaml"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy: true\n", encoding="utf-8")

    runtime = diagnosis_report_path(tmp_path / "data", "1-1")
    runtime.parent.mkdir(parents=True)
    runtime.write_text("runtime: true\n", encoding="utf-8")

    ctx = DiagnosisContext(data_dir=tmp_path / "data")
    path = resolve_report_path(ctx=ctx, section_id="1-1", module_dir=module_dir)
    assert path == runtime


def test_resolve_report_path_falls_back_to_legacy(tmp_path: Path):
    module_dir = tmp_path / "modules" / "1-1"
    legacy = module_dir / "reports" / "latest.yaml"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy: true\n", encoding="utf-8")

    ctx = DiagnosisContext(data_dir=tmp_path / "data")
    path = resolve_report_path(ctx=ctx, section_id="1-1", module_dir=module_dir)
    assert path == legacy
