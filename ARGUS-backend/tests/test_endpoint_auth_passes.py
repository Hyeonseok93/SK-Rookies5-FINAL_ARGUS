"""Tests for origin-scoped diagnosis auth session selection."""

from __future__ import annotations

import json
from pathlib import Path

from diagnosis.endpoint_auth_passes import (
    build_probe_passes,
    filter_sessions_for_probe,
    pick_account_for_login_entry,
)
from inventory.schema import Endpoint


def _session(email: str, login_url: str) -> dict:
    return {
        "email": email,
        "token": "tok",
        "login_url": login_url,
        "login_label": "login",
        "delivery": "cookie",
        "cookie_name": "accessToken",
    }


def test_filter_sessions_matches_origin_not_cross_port():
    user = _session("user@ex.com", "http://localhost:8080/api/v1/auth/login")
    admin = _session("admin@ex.com", "http://localhost:8081/api/v1/auth/admin/login")
    matched = filter_sessions_for_probe(
        base_url="http://localhost:8081",
        path="/api/v1/admin/dashboard",
        sessions=[user, admin],
    )
    assert len(matched) == 1
    assert matched[0]["email"] == "admin@ex.com"


def test_filter_sessions_user_api_allows_origin_matched_accounts():
    user = _session("user@ex.com", "http://localhost:8080/api/v1/auth/login")
    admin = _session("admin@ex.com", "http://localhost:8080/api/v1/auth/admin/login")
    matched = filter_sessions_for_probe(
        base_url="http://localhost:8080",
        path="/api/v1/members/me",
        sessions=[user, admin],
    )
    emails = {s["email"] for s in matched}
    assert emails == {"user@ex.com", "admin@ex.com"}


def test_build_probe_passes_includes_anonymous_and_scoped_sessions():
    ep = Endpoint(
        method="GET",
        path="/api/v1/admin/users",
        base_url="http://localhost:8081",
    )
    admin = _session("admin@ex.com", "http://localhost:8081/api/v1/auth/admin/login")
    user = _session("user@ex.com", "http://localhost:8080/api/v1/auth/login")
    passes = build_probe_passes(ep, [admin, user])
    modes = [p[0] for p in passes]
    assert modes[0] == "anonymous"
    assert len(passes) == 2
    assert "admin@ex.com" in modes[1]


def test_pick_account_for_login_entry_prefers_verify_success(tmp_path: Path):
    login_report = {
        "accounts": [
            {
                "email": "admin@ex.com",
                "successful_login_urls": ["http://localhost:8081/api/v1/auth/admin/login"],
                "failed_login_urls": [],
                "entry_specific": True,
                "exclusive_login_url": "http://localhost:8081/api/v1/auth/admin/login",
            }
        ]
    }
    entry = {"url": "http://localhost:8081/api/v1/auth/admin/login", "label": "login"}
    accounts = [
        {"email": "user@ex.com", "password": "x"},
        {"email": "admin@ex.com", "password": "y"},
    ]
    picked = pick_account_for_login_entry(entry, accounts, login_report)
    assert picked is not None
    assert picked["email"] == "admin@ex.com"


def test_discover_login_entries_keeps_multiple_origins(tmp_path, monkeypatch):
    from app.services.login_discovery_service import discover_login_entries
    from inventory.schema import ApiTree, InputParam, InventoryMeta

    monkeypatch.setattr("app.services.login_discovery_service.DATA_DIR", tmp_path)
    monkeypatch.setattr("app.services.login_discovery_service.probe_url", lambda url: url)
    monkeypatch.setattr(
        "diagnosis.replay.normalize.load_dashboard_base_urls",
        lambda explicit=None: ["http://localhost:8080", "http://localhost:8081"],
    )

    tree = ApiTree(
        meta=InventoryMeta(app_name="test"),
        endpoints=[
            Endpoint(
                method="POST",
                path="/api/v1/auth/admin/login",
                base_url="http://localhost:8080",
                request_params=[
                    InputParam(in_="body", name="email"),
                    InputParam(in_="body", name="password"),
                ],
            ),
            Endpoint(
                method="POST",
                path="/api/v1/auth/admin/login",
                base_url="http://localhost:8081",
                request_params=[
                    InputParam(in_="body", name="email"),
                    InputParam(in_="body", name="password"),
                ],
            ),
        ],
    )
    (tmp_path / "api-tree.json").write_text(
        json.dumps(tree.to_dict(), ensure_ascii=False),
        encoding="utf-8",
    )

    entries = discover_login_entries(
        {"id_field": "email", "pw_field": "password"},
        {"targets": [{"base_url": "http://localhost:8080"}, {"base_url": "http://localhost:8081"}]},
        data_dir=tmp_path,
    )
    urls = {e["url"] for e in entries}
    assert "http://localhost:8080/api/v1/auth/admin/login" in urls
    assert "http://localhost:8081/api/v1/auth/admin/login" in urls
