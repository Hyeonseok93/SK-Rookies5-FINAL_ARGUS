"""Tests for guideline 4-2 token analysis."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
import time
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "4-2"


def _load(name: str):
    mod_name = f"test_g42_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _jwt(payload: dict, *, alg: str = "HS256") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.signature"


def test_jwt_none_algorithm_finding():
    token_mod = _load("token_analyzer")
    now = int(time.time())
    token = _jwt({"iat": now, "exp": now + 3600}, alg="none")
    findings = token_mod.analyze_token(
        token,
        label="access",
        login_url="https://example.com/login",
        email="u@ex.com",
        max_lifetime_sec=1800,
        min_token_length=16,
        min_entropy=3.0,
    )
    rules = {f.evidence.get("rule_id") for f in findings}
    assert "4-2-jwt-weak-alg" in rules


def test_jwt_long_lifetime_finding():
    token_mod = _load("token_analyzer")
    now = int(time.time())
    token = _jwt({"iat": now, "exp": now + 7200})
    findings = token_mod.analyze_token(
        token,
        label="access",
        login_url="https://example.com/login",
        email="u@ex.com",
        max_lifetime_sec=1800,
        min_token_length=16,
        min_entropy=3.0,
    )
    rules = {f.evidence.get("rule_id") for f in findings}
    assert "4-2-jwt-long-lived" in rules


def test_jwt_missing_exp_finding():
    token_mod = _load("token_analyzer")
    token = _jwt({"sub": "user-1"})
    findings = token_mod.analyze_token(
        token,
        label="access",
        login_url="https://example.com/login",
        email="u@ex.com",
        max_lifetime_sec=1800,
        min_token_length=16,
        min_entropy=3.0,
    )
    rules = {f.evidence.get("rule_id") for f in findings}
    assert "4-2-jwt-no-exp" in rules


def test_relogin_same_token_finding(monkeypatch):
    lifecycle = _load("lifecycle_probes")
    session = {
        "email": "u@ex.com",
        "access_token": "same.access.token",
        "refresh_token": "same.refresh.token",
        "token": "same.access.token",
    }

    def fake_login(_cfg, _account, _url, timeout=None):
        return dict(session)

    monkeypatch.setattr(lifecycle, "login_account_at", fake_login)
    finding, stats = lifecycle.probe_relogin_token_uniqueness(
        {},
        {"email": "u@ex.com", "password": "x"},
        "https://example.com/api/v1/auth/login",
        timeout=5.0,
    )
    assert finding is not None
    assert finding.evidence.get("rule_id") == "4-2-token-reuse"
    assert stats["first"]["access"] is True


def test_discover_logout_urls_from_tree(monkeypatch):
    targets = _load("targets")
    from diagnosis.replay import normalize as norm
    from inventory.schema import ApiTree, Endpoint, InventoryMeta

    tree = ApiTree(
        meta=InventoryMeta(app_name="t"),
        endpoints=[
            Endpoint(
                method="POST",
                path="/api/v1/auth/logout",
                base_url="https://onde.click",
            )
        ],
    )
    monkeypatch.setattr(targets, "load_api_tree", lambda _d: tree)
    monkeypatch.setattr(norm, "load_dashboard_base_urls", lambda: ["https://onde.click"])
    urls = targets.discover_logout_urls(
        {"diagnosis_4_2": {"logout_urls": []}},
        data_dir=Path("."),
    )
    assert any("logout" in u for u in urls)


def test_inventory_auth_logout_gap_detects_login_without_logout(monkeypatch):
    targets = _load("targets")
    from diagnosis.replay import normalize as norm
    from inventory.schema import ApiTree, Endpoint, InventoryMeta

    tree = ApiTree(
        meta=InventoryMeta(app_name="t"),
        endpoints=[
            Endpoint(
                method="POST",
                path="/api/v1/auth/login",
                base_url="https://onde.click",
            )
        ],
    )
    monkeypatch.setattr(targets, "load_api_tree", lambda _d: tree)
    monkeypatch.setattr(norm, "load_dashboard_base_urls", lambda: ["https://onde.click"])
    gap = targets.inventory_auth_logout_gap(
        {"diagnosis_4_2": {"logout_urls": []}},
        data_dir=Path("."),
        logout_urls=[],
    )
    assert gap is not None
    assert gap["login_endpoints"]
    assert not gap["logout_endpoints"]


def test_no_server_logout_finding_rule():
    targets = _load("targets")
    finding = targets.no_server_logout_finding(
        {"login_endpoints": ["POST https://onde.click/api/v1/auth/login"]},
        email="u@ex.com",
        login_url="https://onde.click/api/v1/auth/login",
    )
    assert finding.evidence.get("rule_id") == "4-2-no-server-logout-api"
    assert finding.severity == "medium"


def test_client_only_logout_findings(monkeypatch):
    lifecycle = _load("lifecycle_probes")
    session = {
        "email": "u@ex.com",
        "access_token": "access.tok",
        "refresh_token": "refresh.tok",
        "token": "access.tok",
    }

    monkeypatch.setattr(
        lifecycle,
        "login_account_at",
        lambda _cfg, _account, _url, timeout=None: dict(session),
    )
    monkeypatch.setattr(
        lifecycle,
        "probe_auth_check",
        lambda _client, *, base_url, probe_path, session: 200,
    )
    monkeypatch.setattr(
        lifecycle,
        "_probe_refresh_token",
        lambda _client, *, base_url, refresh_path, session: (200, "body"),
    )

    findings, stats = lifecycle.probe_client_only_logout(
        {},
        {"email": "u@ex.com", "password": "x"},
        "https://onde.click/api/v1/auth/login",
        base_url="https://onde.click",
        probe_path="/api/v1/members/me",
        refresh_path="/api/v1/auth/refresh",
        timeout=5.0,
    )
    rules = {f.evidence.get("rule_id") for f in findings}
    assert "4-2-token-valid-after-client-logout" in rules
    assert "4-2-refresh-valid-after-client-logout" in rules
    assert stats["mode"] == "client_only"


def test_duplicate_login_cross_ip_findings(monkeypatch):
    lifecycle = _load("lifecycle_probes")
    session_a = {
        "email": "u@ex.com",
        "access_token": "access.a",
        "token": "access.a",
    }
    session_b = {
        "email": "u@ex.com",
        "access_token": "access.b",
        "token": "access.b",
    }
    login_calls: list[dict[str, str]] = []

    def fake_login(_cfg, _account, _url, timeout=None, extra_headers=None):
        hdrs = dict(extra_headers or {})
        login_calls.append(hdrs)
        return dict(session_a if hdrs.get("X-Forwarded-For") == "10.0.0.1" else session_b)

    monkeypatch.setattr(lifecycle, "login_account_at", fake_login)
    monkeypatch.setattr(
        lifecycle,
        "probe_auth_check",
        lambda _client, *, base_url, probe_path, session, extra_headers=None: 200,
    )

    findings, stats = lifecycle.probe_duplicate_login_cross_ip(
        {},
        {"email": "u@ex.com", "password": "x"},
        "https://onde.click/api/v1/auth/login",
        base_url="https://onde.click",
        probe_path="/api/v1/members/me",
        timeout=5.0,
        client_ips=["10.0.0.1", "10.0.0.2"],
    )
    rules = {f.evidence.get("rule_id") for f in findings}
    assert "4-2-duplicate-login-cross-ip" in rules
    assert "4-2-no-ip-session-binding" in rules
    assert stats["client_ip_a"] == "10.0.0.1"
    assert stats["client_ip_b"] == "10.0.0.2"
    assert len(login_calls) == 2
