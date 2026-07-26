"""Tests for 7-1 HTTP method policy rules and ZAP mapping."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "7-1"


def _load(name: str):
    mod_name = f"diag_g71_{name}_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_classify_trace_echo():
    rules = _load("method_rules")
    issue = rules.classify_trace_response(
        200,
        "TRACE /secret HTTP/1.1\r\nHost: example.com\r\n\r\n",
        request_path="/secret",
    )
    assert issue is not None
    assert issue.issue_type == "trace_echo"
    assert issue.severity == "high"


def test_classify_trace_no_echo():
    rules = _load("method_rules")
    assert rules.classify_trace_response(200, "OK", request_path="/") is None
    assert rules.classify_trace_response(405, "TRACE / HTTP/1.1", request_path="/") is None


def test_classify_allow_dangerous():
    rules = _load("method_rules")
    issues = rules.classify_allow_header("GET, HEAD, TRACE, OPTIONS", strict_risky=False)
    assert len(issues) == 1
    assert issues[0].issue_type == "allow_dangerous"
    assert "TRACE" in issues[0].matched_methods


def test_classify_allow_risky_strict():
    rules = _load("method_rules")
    issues = rules.classify_allow_header("GET, PUT, DELETE", strict_risky=True)
    assert len(issues) == 1
    assert issues[0].issue_type == "allow_risky"
    assert set(issues[0].matched_methods) == {"DELETE", "PUT"}


def test_classify_allow_risky_relaxed():
    rules = _load("method_rules")
    assert rules.classify_allow_header("GET, PUT, DELETE", strict_risky=False) == []


def test_is_71_method_plugin():
    zap = _load("zap_scan")
    assert zap.is_71_method_plugin("90028")
    assert zap.is_71_method_plugin("90028-3")
    assert not zap.is_71_method_plugin("10033")
    assert not zap.is_71_method_plugin("0")


def test_zap_trace_alert_maps_to_7_1_finding():
    zap = _load("zap_scan")
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "90028-3",
            "alert": "TRACE method enabled",
            "url": "http://localhost:8080/",
            "risk": "Medium",
        },
        base_url="http://localhost:8080",
    )
    assert finding is not None
    assert finding.evidence["rule_id"] == "7-1-insecure-http-method"
    assert finding.evidence["issue_type"] == "trace_enabled"
    assert finding.evidence["source"] == "zap"
    assert finding.severity == "high"
