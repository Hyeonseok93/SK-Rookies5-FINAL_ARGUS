"""Tests for guideline 4-1 cookie cross/tamper rules."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "4-1"


def _load(name: str):
    mod_name = f"test_g41_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_cross_session_pairs_all_combinations():
    rules = _load("cookie_rules")
    sessions = [
        {"email": "a@ex.com", "login_url": "http://x/login", "login_label": "login"},
        {"email": "b@ex.com", "login_url": "http://x/login", "login_label": "login"},
        {"email": "a@ex.com", "login_url": "http://x/admin/login", "login_label": "admin"},
    ]
    pairs = rules.cross_session_pairs(sessions)
    assert ("a@ex.com", "http://x/login") != ("a@ex.com", "http://x/admin/login")
    assert len(pairs) == 6
    assert any(p[0]["email"] == "b@ex.com" and p[1]["email"] == "a@ex.com" for p in pairs)


def test_tampered_variants_include_empty_and_garbage():
    rules = _load("cookie_rules")
    session = {"email": "u@ex.com", "token": "abc.def.ghi", "cookie_name": "accessToken", "delivery": "cookie"}
    labels = [label for label, _ in rules.tampered_auth_variants(session, "cookie_access")]
    assert "empty_cookie" in labels
    assert "access_cookie_garbage" in labels


def test_is_admin_api_path():
    rules = _load("cookie_rules")
    assert rules.is_admin_api_path("/api/v1/admin/bookings")
    assert not rules.is_admin_api_path("/api/v1/health")


def test_cross_cookie_leak_requires_identical_nonempty_body():
    rules = _load("cookie_rules")
    owner = {"email": "yerin@travel.com", "member_id": 1}
    other = {"email": "ondecar@travel.com", "member_id": 2}
    owner_body = b'{"success":true,"data":{"email":"yerin@travel.com","id":1,"extra":"padding-for-size-test"}}'
    other_same = owner_body
    other_diff = b'{"success":true,"data":{"email":"ondecar@travel.com","id":2,"extra":"padding-for-size-test"}}'
    assert rules.cross_cookie_leak_detected(owner_body, other_same, owner, other, path="/api/v1/members/me")
    assert not rules.cross_cookie_leak_detected(owner_body, other_diff, owner, other, path="/api/v1/members/me")
    generic = b'{"success":true,"data":{"content":[]},"message":"same-for-all-users-generic-response"}'
    assert not rules.cross_cookie_leak_detected(generic, generic, owner, other, path="/api/v1/members/me")
    assert not rules.cross_cookie_leak_detected(owner_body, owner_body, owner, other, path="/api/v1")
