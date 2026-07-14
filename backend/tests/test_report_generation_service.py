from __future__ import annotations

from pathlib import Path

from app.services import report_generation_service


def test_report_support_is_discovered_from_generator(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(report_generation_service, "BACKEND_ROOT", tmp_path)
    assert report_generation_service.supports("1-2") is False
    script = tmp_path / "report" / "modules" / "1-2" / "generate.py"
    script.parent.mkdir(parents=True)
    script.write_text("# stub\n", encoding="utf-8")
    assert report_generation_service.supports("1-2") is True


def test_resolve_report_file_rejects_unlisted_name(tmp_path: Path):
    assert report_generation_service.resolve_report_file("1-2", "../../config.yaml", tmp_path) is None

