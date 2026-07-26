"""Tests for diagnosis report path resolution."""

from __future__ import annotations

from pathlib import Path

from diagnosis.context import DiagnosisContext
from diagnosis.paths import resolve_report_path, section_report_path


def test_resolve_report_path_uses_data_report(tmp_path: Path):
    runtime = section_report_path(tmp_path / "data", "1-1")
    runtime.parent.mkdir(parents=True)
    runtime.write_text("runtime: true\n", encoding="utf-8")

    ctx = DiagnosisContext(data_dir=tmp_path / "data")
    path = resolve_report_path(ctx=ctx, section_id="1-1", module_dir=tmp_path / "modules" / "1-1")
    assert path == runtime


def test_section_report_path_layout(tmp_path: Path):
    path = section_report_path(tmp_path / "data", "7-3")
    assert path == tmp_path / "data" / "report" / "7-3" / "latest.yaml"
