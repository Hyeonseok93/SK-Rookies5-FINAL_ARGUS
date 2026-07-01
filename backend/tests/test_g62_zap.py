"""Tests for 6-2 ZAP username enumeration (40023) helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "6-2" / "zap_scan.py"


def _load():
    mod_name = "diag_g62_zap_scan_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_is_username_enum_plugin():
    zap = _load()
    assert zap.is_username_enum_plugin("40023") is True
    assert zap.is_username_enum_plugin("10035") is False


def test_zap_alert_to_finding():
    zap = _load()
    finding = zap.zap_alert_to_finding(
        {
            "pluginId": "40023",
            "alert": "Possible Username Enumeration",
            "url": "http://localhost:8080/api/v1/auth/login",
            "param": "email",
            "risk": "Medium",
            "other": "differs for valid vs invalid user",
        },
        login_url="http://localhost:8080/api/v1/auth/login",
        login_label="login",
    )
    assert finding is not None
    assert finding.severity == "medium"
    assert finding.evidence["source"] == "zap"
    assert finding.evidence["plugin_id"] == "40023"


def test_auth_method_api_vs_page():
    zap = _load()
    assert (
        zap._auth_method_for_entry({"kind": "api"}, "http://localhost:8080/api/v1/auth/login")
        == "jsonBasedAuthentication"
    )
    assert (
        zap._auth_method_for_entry({"kind": "page"}, "http://localhost:5173/login")
        == "formBasedAuthentication"
    )


def test_login_request_data_json():
    zap = _load()
    raw = zap._login_request_data("email", "password", json_body=True)
    assert "{%username%}" in raw
    assert "{%password%}" in raw
    assert '"email"' in raw
