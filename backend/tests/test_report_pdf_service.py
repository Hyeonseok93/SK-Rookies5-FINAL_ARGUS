from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from app.services import report_pdf_service as svc
from diagnosis.context import DiagnosisContext


def _load_g15_selector():
    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "1-5" / "selector.py"
    spec = importlib.util.spec_from_file_location("g15_selector_pdf_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    "evidence",
    [
        {
            "rule_id": "1-5-cors-misconfig",
            "url": "http://192.168.0.55:8081",
        },
        {
            "rule_id": "1-5-reflected-xss-probe",
            "test_url": "http://localhost:8080/api/v1/members/me/profile?userId=1#name",
            "url": "http://localhost:8080/api/v1/members/me/profile?userId=1",
            "param_name": "name",
        },
        {
            "rule_id": "1-5-open-redirect",
            "test_url": "http://localhost:8080/redirect?next=https://evil.example",
            "baseline_url": "http://localhost:8080/redirect?next=/home",
            "param_name": "next",
        },
    ],
)
def test_g15_case_id_matches_screenshot_selector(evidence: dict):
    """report_pdf_service duplicates selector.py's dedupe key on purpose
    (avoids a bare-module-name import collision) — this pins the two
    implementations together so a change to one is caught here."""
    selector = _load_g15_selector()
    finding = {"severity": "high", "evidence": evidence}
    assert svc._g15_case_id(evidence) == selector.stable_finding_id(finding)


def test_g15_target_url_prefers_test_url_over_location():
    evidence = {
        "location": "REFLECTED_XSS:<script>x</script>",
        "test_url": "http://localhost:8080/api/v1/posts/1#content",
        "url": "http://localhost:8080/api/v1/posts/1",
    }
    assert svc._g15_target_url(evidence) == "http://localhost:8080/api/v1/posts/1"


def test_g15_status_line_formats_baseline_and_test():
    assert svc._g15_status_line({"baseline_status": 201, "test_status": 200}) == "HTTP 201 → 200"
    assert svc._g15_status_line({"http_status": 500}) == "HTTP 500"
    assert svc._g15_status_line({}) == ""


def test_report_pdf_filename_includes_section_id():
    name = svc.report_pdf_filename("1-5")
    assert name.startswith("argus-1-5-report-")
    assert name.endswith(".pdf")


def test_render_report_pdf_raises_when_no_report(tmp_path: Path):
    ctx = DiagnosisContext(data_dir=tmp_path / "data")
    with pytest.raises(FileNotFoundError):
        svc.render_report_pdf("1-5", ctx=ctx)


def test_render_report_pdf_for_1_5_produces_pdf_bytes(tmp_path: Path):
    from diagnosis.paths import section_report_path

    report_path = section_report_path(tmp_path / "data", "1-5")
    report_path.parent.mkdir(parents=True)
    report_path.write_text(
        """
section_id: 1-5
title: 검증되지 않은 리다이렉트와 포워드
chapter: 1
status: fail
implemented: true
findings:
- severity: high
  message: 'CORS misconfiguration: http://example.test'
  evidence:
    rule_id: 1-5-cors-misconfig
    url: http://example.test
    acao: https://evil.example
    acac: 'true'
message: '1-5 redirect/CORS: 1 high finding(s)'
checked_at: '2026-07-10T05:03:58+00:00'
""".strip(),
        encoding="utf-8",
    )

    ctx = DiagnosisContext(data_dir=tmp_path / "data")
    pdf_bytes = svc.render_report_pdf("1-5", ctx=ctx)

    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000
