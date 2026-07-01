"""Tests for shared diagnosis probe auth helpers."""

from diagnosis.probe_auth import session_auth_mode, session_probe_tag


def test_session_auth_mode_distinct_per_login():
    user = {"email": "user@ex.com", "login_label": "login", "login_url": "http://x/login"}
    admin = {"email": "admin@ex.com", "login_label": "admin", "login_url": "http://x/admin/login"}
    assert session_auth_mode(user) == "authenticated:user@ex.com:login"
    assert session_auth_mode(admin) == "authenticated:admin@ex.com:admin"
    assert session_auth_mode(user) != session_auth_mode(admin)


def test_session_probe_tag_human_readable():
    session = {"email": "yerin@travel.com", "login_label": "admin"}
    assert session_probe_tag(session) == "yerin@travel.com · admin"


def test_all_account_auths_dedupes(monkeypatch):
    from diagnosis import probe_auth

    def fake_resolve(auth_cfg, accounts, *, data_dir=None, refresh=False):
        return (
            [
                {"email": "a@ex.com", "login_url": "http://x/login", "login_label": "login", "token": "1"},
                {"email": "b@ex.com", "login_url": "http://x/admin/login", "login_label": "admin", "token": "2"},
            ],
            {"source": "verify_cache", "sessions": 2},
        )

    monkeypatch.setattr(probe_auth, "resolve_account_auths", fake_resolve)
    monkeypatch.setattr(
        probe_auth,
        "load_test_accounts",
        lambda: {"accounts": [{"email": "a@ex.com", "password": "x"}]},
    )

    sessions = probe_auth.all_account_auths({"auth": {}})
    assert len(sessions) == 2
