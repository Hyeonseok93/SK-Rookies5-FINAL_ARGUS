"""Tests for diagnosis run cancellation."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from app.services import diagnosis_progress as dp
from app.services import diagnosis_service
from diagnosis.result import SectionReport, utc_now_iso


def _fake_report(section_id: str = "6-1", *, status: str = "pass") -> SectionReport:
    return SectionReport(
        section_id=section_id,
        title="test",
        chapter=6,
        status=status,
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


def test_request_cancel_run_sets_flag():
    dp.reset(section_id="6-1", message="running")
    assert diagnosis_service.request_cancel_run() == "6-1"
    assert dp.is_cancel_requested() is True
    assert dp.snapshot()["phase"] == "cancelling"


def test_request_cancel_run_without_active_run_returns_none():
    dp.finish("reset")
    assert diagnosis_service.request_cancel_run() is None


def test_cancelled_report_finishes_with_cancelled_phase(monkeypatch):
    mod = MagicMock()
    mod.diagnosable = True
    mod.run.return_value = _fake_report(status="cancelled")
    monkeypatch.setattr(diagnosis_service, "_resolve_module", lambda _sid: mod)

    diagnosis_service.start_section_run_background("6-1")

    deadline = time.time() + 3.0
    while time.time() < deadline:
        snap = dp.snapshot()
        if not snap["running"] and snap["phase"] == "cancelled":
            break
        time.sleep(0.05)
    else:
        pytest.fail("cancelled run did not finish")

    assert dp.snapshot()["phase"] == "cancelled"
