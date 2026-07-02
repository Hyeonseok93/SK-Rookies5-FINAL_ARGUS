"""Tests for inventory-based login endpoint discovery."""

from __future__ import annotations

import json
from pathlib import Path

from app.services.auth_probe_service import configured_login_entries
from app.services.login_discovery_service import (
    discover_login_entries,
    is_login_candidate,
    resolve_login_entries,
)
from app.services.login_endpoints_service import (
    dashboard_login_entries,
    resolve_login_endpoint_url,
    save_login_endpoints,
)
from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta


def _ep(
    *,
    method: str = "POST",
    path: str,
    base: str = "http://localhost:8080",
    params: list[InputParam] | None = None,
    kind: str = "api",
) -> Endpoint:
    return Endpoint(
        method=method,
        path=path,
        base_url=base,
        request_params=params or [],
        kind=kind,
    )


def _write_tree(tmp_path: Path, *endpoints: Endpoint) -> Path:
    tree = ApiTree(meta=InventoryMeta(app_name="test"), endpoints=list(endpoints))
    path = tmp_path / "api-tree.json"
    path.write_text(json.dumps(tree.to_dict(), ensure_ascii=False), encoding="utf-8")
    return path


def _patch_dashboard(monkeypatch, bases: list[str]) -> None:
    monkeypatch.setattr(
        "diagnosis.replay.normalize.load_dashboard_base_urls",
        lambda explicit=None: [u.rstrip("/") for u in (explicit if explicit is not None else bases) if u.strip()],
    )


def test_is_login_candidate_matches_auth_login():
    ep = _ep(
        path="/api/v1/auth/login",
        params=[
            InputParam(in_="body", name="email"),
            InputParam(in_="body", name="password"),
        ],
    )
    assert is_login_candidate(ep, {"id_field": "email", "pw_field": "password"}) is True


def test_is_login_candidate_rejects_refresh():
    ep = _ep(path="/api/v1/auth/refresh", params=[])
    assert is_login_candidate(ep, {}) is False


def test_discover_prefers_api_base_over_frontend_proxy(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.login_discovery_service.DATA_DIR", tmp_path)
    monkeypatch.setattr(
        "app.services.login_discovery_service.probe_url",
        lambda url: url,
    )
    _patch_dashboard(monkeypatch, ["http://localhost:8080"])
    _write_tree(
        tmp_path,
        _ep(
            path="/api/v1/auth/login",
            base="http://localhost:5173",
            kind="frontend",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
        _ep(
            path="/api/v1/auth/login",
            base="http://localhost:8080",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
        _ep(
            path="/api/v1/auth/admin/login",
            base="http://localhost:8080",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
    )

    entries = discover_login_entries(
        {"id_field": "email", "pw_field": "password"},
        {"targets": [{"base_url": "http://localhost:8080"}]},
        data_dir=tmp_path,
    )
    urls = {e["url"] for e in entries}
    assert "http://localhost:8080/api/v1/auth/login" in urls
    assert "http://localhost:8080/api/v1/auth/admin/login" in urls
    assert all("5173" not in u for u in urls)
    assert all(e["source"] == "inventory" for e in entries)


def test_configured_login_entries_ignores_config_yaml_login_url(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.login_discovery_service.DATA_DIR", tmp_path)
    monkeypatch.setattr(
        "app.services.login_discovery_service.probe_url",
        lambda url: url,
    )
    _patch_dashboard(monkeypatch, [])
    monkeypatch.setattr(
        "app.services.login_discovery_service._load_raw_config",
        lambda: {
            "auth": {
                "login_url": "http://localhost:9999/api/v1/auth/login",
                "id_field": "email",
                "pw_field": "password",
            },
            "targets": [{"base_url": "http://localhost:8080"}],
        },
    )
    _write_tree(
        tmp_path,
        _ep(
            path="/api/v1/auth/login",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
    )

    entries = configured_login_entries(
        {"login_url": "http://localhost:9999/api/v1/auth/login"},
    )
    assert len(entries) == 1
    assert entries[0]["url"] == "http://localhost:8080/api/v1/auth/login"
    assert "9999" not in entries[0]["url"]


def test_resolve_login_url_path(monkeypatch):
    monkeypatch.setattr(
        "app.services.login_endpoints_service.probe_url",
        lambda url: url,
    )
    _patch_dashboard(monkeypatch, [])
    raw = {"targets": [{"base_url": "http://localhost:8080"}]}
    assert (
        resolve_login_endpoint_url("/api/v1/auth/login", raw)
        == "http://localhost:8080/api/v1/auth/login"
    )


def test_dashboard_login_entries_merge(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.login_endpoints_service.LOGIN_ENDPOINTS_PATH", tmp_path / "le.json")
    monkeypatch.setattr("app.services.login_discovery_service.DATA_DIR", tmp_path)
    monkeypatch.setattr(
        "app.services.login_discovery_service.probe_url",
        lambda url: url,
    )
    monkeypatch.setattr(
        "app.services.login_endpoints_service.probe_url",
        lambda url: url,
    )
    _patch_dashboard(monkeypatch, ["http://localhost:8080"])
    _write_tree(
        tmp_path,
        _ep(
            path="/api/v1/auth/login",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
    )
    save_login_endpoints(
        [
            {
                "id": "1",
                "url": "http://localhost:8080/api/v1/auth/custom-modal-login",
                "kind": "api",
            }
        ]
    )
    raw = {"targets": [{"base_url": "http://localhost:8080"}]}
    merged = resolve_login_entries({"id_field": "email", "pw_field": "password"}, raw, data_dir=tmp_path)
    urls = {e["url"] for e in merged}
    assert "http://localhost:8080/api/v1/auth/login" in urls
    assert "http://localhost:8080/api/v1/auth/custom-modal-login" in urls
    manual = dashboard_login_entries(raw)
    assert manual[0]["source"] == "dashboard"
    assert manual[0]["kind"] == "api"
    assert manual[0]["label"] == "custom-modal-login"


def test_resolve_login_entries_includes_explicit_config_urls(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.login_discovery_service.DATA_DIR", tmp_path)
    _patch_dashboard(monkeypatch, ["http://localhost:8080"])
    _write_tree(tmp_path)
    raw = {"targets": [{"base_url": "http://localhost:8080"}]}
    entries = resolve_login_entries(
        {"login_urls": ["http://localhost:8080/api/v1/auth/login"]},
        raw,
        data_dir=tmp_path,
    )
    assert entries[0]["url"] == "http://localhost:8080/api/v1/auth/login"
    assert entries[0]["source"] == "config"


def test_discover_limits_to_dashboard_production_bases(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.login_discovery_service.DATA_DIR", tmp_path)
    monkeypatch.setattr(
        "app.services.login_discovery_service.probe_url",
        lambda url: url,
    )
    _patch_dashboard(monkeypatch, ["https://onde.click", "https://rookies.onde.click"])
    _write_tree(
        tmp_path,
        _ep(
            path="/api/v1/auth/login",
            base="https://onde.click",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
        _ep(
            path="/api/v1/auth/login",
            base="http://localhost:8080",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
        _ep(
            path="/api/v1/auth/login",
            base="http://localhost:5173",
            params=[
                InputParam(in_="body", name="email"),
                InputParam(in_="body", name="password"),
            ],
        ),
    )
    entries = discover_login_entries(
        {"id_field": "email", "pw_field": "password"},
        {
            "targets": [{"base_url": "http://host.docker.internal:8080"}],
            "inventory": {"markdown": {"frontend_base_url": "http://localhost:5173"}},
        },
        data_dir=tmp_path,
    )
    assert len(entries) == 1
    assert entries[0]["url"] == "https://onde.click/api/v1/auth/login"
