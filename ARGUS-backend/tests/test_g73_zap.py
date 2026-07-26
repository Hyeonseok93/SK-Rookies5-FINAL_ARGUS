"""Tests for 7-3 ZAP header disclosure integration."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "7-3"


def _load_zap_scan():
    mod_name = "diag_g73_zap_scan_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "zap_scan.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_is_73_header_plugin():
    zap = _load_zap_scan()
    assert zap.is_73_header_plugin("10037")
    assert zap.is_73_header_plugin("10036")
    assert zap.is_73_header_plugin("10036-2")
    assert not zap.is_73_header_plugin("0")
    assert not zap.is_73_header_plugin("10033")


def test_zap_server_alert_maps_to_7_3_finding():
    zap = _load_zap_scan()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "10036-2",
            "alert": "Server Leaks Version Information via Server HTTP Response Header Field",
            "url": "http://localhost:5173/",
            "risk": "Low",
            "evidence": "nginx/1.31.2",
        },
        base_url="http://localhost:5173",
    )
    assert finding is not None
    assert finding.evidence["rule_id"] == "7-3-header-disclosure"
    assert finding.evidence["header"] == "server"
    assert finding.evidence["source"] == "zap"


def test_zap_x_powered_by_maps_to_7_3_finding():
    zap = _load_zap_scan()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "10037",
            "alert": "Server Leaks Information via X-Powered-By HTTP Response Header Field(s)",
            "url": "http://localhost:8080/",
            "risk": "Low",
        },
        base_url="http://localhost:8080",
    )
    assert finding is not None
    assert finding.evidence["header"] == "x-powered-by"
