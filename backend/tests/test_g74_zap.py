"""Tests for 7-4 ZAP mapping."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "7-4" / "zap_scan.py"


def _load_zap():
    mod_name = "diag_g74_zap_scan_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_is_74_security_plugin():
    zap = _load_zap()
    assert zap.is_74_security_plugin("10035")
    assert zap.is_74_security_plugin("10038")
    assert not zap.is_74_security_plugin("10036")


def test_zap_hsts_alert_maps_to_finding():
    zap = _load_zap()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "10035",
            "alert": "Strict-Transport-Security Header Not Set",
            "url": "https://example.com/",
            "risk": "Low",
        },
        base_url="https://example.com",
    )
    assert finding is not None
    assert finding.evidence["check_type"] == "missing_hsts"
    assert finding.evidence["engine"] == "zap"
