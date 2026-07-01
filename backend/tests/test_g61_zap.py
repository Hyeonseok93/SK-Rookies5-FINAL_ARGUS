"""Tests for 6-1 ZAP error disclosure (90022 / 10023) helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "6-1" / "zap_scan.py"


def _load():
    mod_name = "diag_g61_zap_scan_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_is_61_error_plugin():
    zap = _load()
    assert zap.is_61_error_plugin("90022") is True
    assert zap.is_61_error_plugin("10023") is True
    assert zap.is_61_error_plugin("40023") is False


def test_zap_alert_to_finding_90022():
    zap = _load()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "90022",
            "alert": "Application Error Disclosure",
            "url": "http://localhost:8080/api/v1/foo",
            "param": "id",
            "risk": "Medium",
            "other": "stack trace in body",
        },
        base_url="http://localhost:8080",
    )
    assert finding is not None
    assert finding.severity == "medium"
    assert finding.evidence["source"] == "zap"
    assert finding.evidence["engine"] == "zap-native"
    assert finding.evidence["plugin_id"] == "90022"


def test_zap_alert_to_finding_10023():
    zap = _load()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "10023",
            "alert": "Information Disclosure - Debug Error Messages",
            "url": "http://localhost:8080/api/v1/bar",
            "risk": "Low",
        },
        base_url="http://localhost:8080",
    )
    assert finding is not None
    assert finding.evidence["plugin_id"] == "10023"
