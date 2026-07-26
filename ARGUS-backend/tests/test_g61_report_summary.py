"""Tests for 6-1 report summary aggregation."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from diagnosis.result import DiagnosisFinding


def _load_report_summary():
    mod_dir = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "6-1"
    spec = importlib.util.spec_from_file_location("diag_g61_report_summary", mod_dir / "report_summary.py")
    assert spec and spec.loader
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    return rs


def test_build_g61_summary_groups_findings():
    rs = _load_report_summary()
    findings = [
        DiagnosisFinding(
            severity="info",
            message="6-1 scan statistics",
            evidence={"stats": {"endpoints_probed": 2, "requests_sent": 10}},
        ),
        DiagnosisFinding(
            severity="high",
            message="leak",
            evidence={
                "category": "stack_trace",
                "rule_id": "java_stack",
                "sk_class": "exception",
                "hint": "Java stack frame",
                "url": "http://localhost:8080/api/x",
                "base_url": "http://localhost:8080",
                "method": "get",
                "engine": "httpx",
                "source": "httpx",
                "trigger_family": "param",
                "status_code": 500,
                "remediation": "hide stack",
            },
        ),
        DiagnosisFinding(
            severity="high",
            message="leak2",
            evidence={
                "category": "stack_trace",
                "rule_id": "java_stack",
                "hint": "Java stack frame",
                "url": "http://localhost:8080/api/y",
                "base_url": "http://localhost:8080",
                "method": "post",
                "engine": "httpx",
                "source": "httpx",
                "trigger_family": "body",
                "status_code": 500,
            },
        ),
    ]
    summary = rs.build_g61_summary_from_findings(findings)
    assert summary["total_issues"] == 2
    assert summary["by_severity"]["high"] == 2
    assert summary["by_sk"]["exception"] == 2
    assert len(summary["groups"]) == 1
    assert summary["groups"][0]["count"] == 2
    assert summary["groups"][0]["engines"] == ["httpx"]
    assert summary["stats"]["endpoints_probed"] == 2


def test_summary_merges_httpx_and_zap():
    rs = _load_report_summary()
    findings = [
        DiagnosisFinding(
            severity="medium",
            message="zap",
            evidence={
                "category": "zap_error_disclosure",
                "rule_id": "6-1-zap-90022",
                "sk_class": "http",
                "url": "http://localhost:8080/api/x",
                "base_url": "http://localhost:8080",
                "engine": "zap",
                "source": "zap",
            },
        ),
        DiagnosisFinding(
            severity="medium",
            message="httpx",
            evidence={
                "category": "verbose_error",
                "rule_id": "verbose_500_body",
                "sk_class": "http",
                "url": "http://localhost:8080/api/y",
                "base_url": "http://localhost:8080",
                "engine": "httpx",
                "source": "httpx",
                "status_code": "500",
            },
        ),
    ]
    summary = rs.build_g61_summary_from_findings(findings)
    assert summary["total_issues"] == 2
    assert len(summary["groups"]) == 2
