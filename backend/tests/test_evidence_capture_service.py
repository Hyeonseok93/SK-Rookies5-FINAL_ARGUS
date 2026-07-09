from __future__ import annotations

from pathlib import Path

from app.services import evidence_capture_service


def test_unsupported_section_is_ignored(tmp_path: Path):
    result = evidence_capture_service.capture_after_diagnosis("2-2", tmp_path)
    assert result == {"attempted": False, "ok": True}


def test_missing_capture_script_records_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(evidence_capture_service, "BACKEND_ROOT", tmp_path)
    report = tmp_path / "data" / "report" / "1-2" / "latest.yaml"
    report.parent.mkdir(parents=True)
    report.write_text("section_id: 1-2\n", encoding="utf-8")

    result = evidence_capture_service.capture_after_diagnosis("1-2", tmp_path / "data")

    assert result["ok"] is False
    assert "missing" in result["error"].lower()
    assert (
        tmp_path / "data" / "report" / "1-2" / "evidence" / "capture-error.json"
    ).is_file()
