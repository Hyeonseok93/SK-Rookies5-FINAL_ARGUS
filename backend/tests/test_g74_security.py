"""Tests for 7-4 security_rules."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "7-4" / "security_rules.py"


def _load_rules():
    mod_name = "diag_g74_security_rules_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_missing_hsts_on_https():
    rules = _load_rules()
    issues = rules.scan_response_security(
        "https://example.com/",
        {"content-type": "text/html"},
        rules=rules.ScanRules(strict=True),
    )
    types = {i.check_type for i in issues}
    assert "missing_hsts" in types
    assert "missing_csp" in types
    assert "missing_x_frame_options" in types


def test_hsts_not_checked_on_http():
    rules = _load_rules()
    issues = rules.scan_response_security(
        "http://example.com/",
        {},
        rules=rules.ScanRules(strict=True),
    )
    types = {i.check_type for i in issues}
    assert "missing_hsts" not in types


def test_secure_headers_pass():
    rules = _load_rules()
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    issues = rules.scan_response_security(
        "https://example.com/",
        headers,
        rules=rules.ScanRules(strict=True),
    )
    assert issues == []


def test_cookie_missing_secure():
    rules = _load_rules()
    issues = rules.scan_response_security(
        "https://example.com/",
        {"set-cookie": "session=abc; Path=/"},
        rules=rules.ScanRules(strict=True),
        set_cookie_lines=["session=abc; Path=/"],
    )
    types = {i.check_type for i in issues}
    assert "cookie_missing_secure" in types


def test_cookie_samesite_none_requires_secure():
    rules = _load_rules()
    issues = rules.scan_response_security(
        "https://example.com/",
        {},
        rules=rules.ScanRules(strict=True),
        set_cookie_lines=["token=abc; SameSite=None; Path=/"],
    )
    types = {i.check_type for i in issues}
    assert "cookie_samesite_none_insecure" in types


def test_relaxed_mode_lowers_severity():
    rules = _load_rules()
    strict = rules.scan_response_security(
        "https://example.com/",
        {},
        rules=rules.ScanRules(strict=True),
    )
    relaxed = rules.scan_response_security(
        "https://example.com/",
        {},
        rules=rules.ScanRules(strict=False),
    )
    strict_hsts = next(i for i in strict if i.check_type == "missing_hsts")
    relaxed_hsts = next(i for i in relaxed if i.check_type == "missing_hsts")
    assert strict_hsts.severity == "medium"
    assert relaxed_hsts.severity == "low"


def test_scan_rules_from_config():
    rules = _load_rules()
    cfg = rules.scan_rules_from_config(
        {"diagnosis_7_4": {"strict": False, "check_cookies": False}}
    )
    assert cfg.strict is False
    assert cfg.check_cookies is False
