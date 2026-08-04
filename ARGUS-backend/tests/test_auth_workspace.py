from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth_users import create_user, find_user_by_username
from app.main import app
from app.services import diagnosis_progress as dp
from app.services.test_accounts_service import load_test_accounts, save_test_accounts
from app.workspace import ROOT_DATA, bind_workspace, reset_workspace, user_data_dir


@pytest.fixture()
def isolated_root(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setattr("app.workspace.ROOT_DATA", root)
    monkeypatch.setattr("app.workspace.USERS_DIR", root / "users")
    monkeypatch.setattr("app.workspace.USERS_FILE", root / "users.json")
    monkeypatch.setattr("app.auth_users.ROOT_DATA", root)
    monkeypatch.setattr("app.auth_users.USERS_FILE", root / "users.json")
    return root


@pytest.fixture()
def client(isolated_root):
    return TestClient(app)


def test_register_login_me_and_isolation(client, isolated_root):
    r1 = client.post("/api/auth/register", json={"username": "alice", "password": "secret1"})
    assert r1.status_code == 200
    token_a = r1.json()["access_token"]
    user_a = r1.json()["user"]

    r2 = client.post("/api/auth/register", json={"username": "bob", "password": "secret2"})
    assert r2.status_code == 200
    token_b = r2.json()["access_token"]

    denied = client.get("/api/inventory/stats")
    assert denied.status_code == 401

    save_a = client.put(
        "/api/base-urls",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"urls": [{"id": "1", "url": "http://alice.test:8080", "kind": "api"}]},
    )
    assert save_a.status_code == 200
    assert len(save_a.json()["urls"]) == 1

    bob_urls = client.get("/api/base-urls", headers={"Authorization": f"Bearer {token_b}"})
    assert bob_urls.status_code == 200
    assert bob_urls.json()["urls"] == []

    alice_urls = client.get("/api/base-urls", headers={"Authorization": f"Bearer {token_a}"})
    assert alice_urls.json()["urls"][0]["url"] == "http://alice.test:8080"

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["id"] == user_a["id"]

    assert (isolated_root / "users" / user_a["id"] / "base-urls.json").is_file()


def test_accounts_encrypted_and_masked(isolated_root):
    user = create_user("carol", "secret3")
    data_dir = user_data_dir(user["id"])
    tokens = bind_workspace(user_id=user["id"], data_dir=data_dir)
    try:
        saved = save_test_accounts(
            data_dir,
            [{"id": "a1", "email": "c@test.com", "password": "p@ss"}],
        )
        assert saved["accounts"][0]["password"] == "********"
        plain = load_test_accounts(data_dir, mask=False)
        assert plain["accounts"][0]["password"] == "p@ss"
        raw = json.loads((data_dir / "test-accounts.json").read_text(encoding="utf-8"))
        assert raw["accounts"][0]["password"].startswith("enc:")
        assert "p@ss" not in raw["accounts"][0]["password"]
    finally:
        reset_workspace(tokens)


def test_diagnosis_progress_isolated_per_user(isolated_root):
    a = create_user("dave", "secret4")
    b = create_user("erin", "secret5")
    tokens_a = bind_workspace(user_id=a["id"], data_dir=user_data_dir(a["id"]))
    try:
        dp.reset(section_id="1-1", message="alice run", user_id=a["id"])
    finally:
        reset_workspace(tokens_a)

    tokens_b = bind_workspace(user_id=b["id"], data_dir=user_data_dir(b["id"]))
    try:
        snap_b = dp.snapshot(user_id=b["id"])
        assert snap_b.get("running") is False
        dp.reset(section_id="2-1", message="bob run", user_id=b["id"])
        snap_a = dp.snapshot(user_id=a["id"])
        assert snap_a["section_id"] == "1-1"
        assert snap_a["running"] is True
        snap_b2 = dp.snapshot(user_id=b["id"])
        assert snap_b2["section_id"] == "2-1"
    finally:
        reset_workspace(tokens_b)


def test_login_rejects_bad_password(client, isolated_root):
    create_user("frank", "secret6")
    bad = client.post("/api/auth/login", json={"username": "frank", "password": "nope!!"})
    assert bad.status_code == 401
    assert find_user_by_username("frank") is not None


def test_register_disabled_in_production(client, monkeypatch):
    monkeypatch.setenv("ARGUS_ENV", "production")
    monkeypatch.delenv("ARGUS_ALLOW_PUBLIC_REGISTER", raising=False)
    blocked = client.post(
        "/api/auth/register",
        json={"username": "produser", "password": "secret99"},
    )
    assert blocked.status_code == 403


def test_require_secret_fail_closed_in_production(monkeypatch):
    from app.runtime_env import require_secret

    monkeypatch.setenv("ARGUS_ENV", "production")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        require_secret("JWT_SECRET", min_len=32)
