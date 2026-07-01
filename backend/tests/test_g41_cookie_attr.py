"""Tests for 4-1 cookie attribute static analysis."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from diagnosis.cookie_flags import scan_cookie_attributes

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "4-1"


def _load(name: str):
    mod_name = f"test_g41_attr_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_scan_access_token_missing_httponly():
    issues = scan_cookie_attributes(
        ["accessToken=abc; Path=/; Secure; SameSite=Lax"],
        is_https=True,
        strict=True,
        auth_cookie_names={"accessToken"},
    )
    types = {i.check_type for i in issues}
    assert "cookie_missing_httponly" in types


def test_scan_samesite_none_requires_secure():
    issues = scan_cookie_attributes(
        ["accessToken=abc; SameSite=None; Path=/"],
        is_https=False,
        strict=True,
        auth_cookie_names={"accessToken"},
    )
    types = {i.check_type for i in issues}
    assert "cookie_samesite_none_insecure" in types


def test_make_cookie_attr_finding():
    rules = _load("cookie_rules")
    from diagnosis.cookie_flags import CookieFlagIssue

    issue = CookieFlagIssue(
        check_type="cookie_missing_httponly",
        reason="Auth/session cookie without HttpOnly",
        severity="high",
        cookie_name="accessToken",
        cookie_flags="accessToken=x; Secure",
    )
    finding = rules.make_cookie_attr_finding(
        issue=issue,
        sample={
            "login_url": "http://x/login",
            "login_label": "login",
            "email": "u@ex.com",
            "source": "live_login",
            "is_https": False,
        },
    )
    assert finding.evidence["rule_id"] == "4-1-cookie-missing-httponly"
    assert finding.severity == "high"
