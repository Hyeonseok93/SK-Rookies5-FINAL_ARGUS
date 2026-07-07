"""Tests for async 6-1 diagnosis run."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from app.services import diagnosis_progress as dp
from app.services import diagnosis_service
from diagnosis.result import SectionReport, utc_now_iso


def _fake_report(section_id: str = "6-1") -> SectionReport:
    return SectionReport(
        section_id=section_id,
        title="test",
        chapter=6,
        status="pass",
        implemented=True,
        findings=[],
        message="ok",
        checked_at=utc_now_iso(),
    )


@pytest.fixture(autouse=True)
def _clear_progress():
    dp.finish("reset")
    yield
    dp.finish("reset")


def test_start_section_run_background_completes(monkeypatch):
    mod = MagicMock()
    mod.diagnosable = True

    def slow_run(_ctx):
        time.sleep(0.15)
        return _fake_report()

    mod.run.side_effect = slow_run
    monkeypatch.setattr(diagnosis_service, "_resolve_module", lambda _sid: mod)

    diagnosis_service.start_section_run_background("6-1", g61_options={"probe_mode": "sample"})
    time.sleep(0.02)
    assert dp.snapshot()["running"] is True
    assert dp.snapshot()["section_id"] == "6-1"

    deadline = time.time() + 3.0
    while time.time() < deadline:
        snap = dp.snapshot()
        if not snap["running"] and snap["phase"] == "done":
            break
        time.sleep(0.05)
    else:
        pytest.fail("background run did not finish")

    mod.run.assert_called_once()
    assert dp.snapshot()["phase"] == "done"


def test_start_section_run_background_rejects_concurrent(monkeypatch):
    mod = MagicMock()
    mod.diagnosable = True

    def slow_run(_ctx):
        time.sleep(0.3)
        return _fake_report()

    mod.run.side_effect = slow_run
    monkeypatch.setattr(diagnosis_service, "_resolve_module", lambda _sid: mod)

    diagnosis_service.start_section_run_background("6-1")
    with pytest.raises(RuntimeError, match="already running"):
        diagnosis_service.start_section_run_background("6-1")

    deadline = time.time() + 3.0
    while time.time() < deadline and dp.snapshot()["running"]:
        time.sleep(0.05)


def test_start_section_run_background_records_failure(monkeypatch):
    mod = MagicMock()
    mod.diagnosable = True
    mod.run.side_effect = RuntimeError("boom")
    monkeypatch.setattr(diagnosis_service, "_resolve_module", lambda _sid: mod)

    diagnosis_service.start_section_run_background("6-1")

    deadline = time.time() + 3.0
    while time.time() < deadline:
        snap = dp.snapshot()
        if not snap["running"] and snap["phase"] == "error":
            break
        time.sleep(0.05)
    else:
        pytest.fail("background run did not fail")

    assert "boom" in str(dp.snapshot()["message"])
