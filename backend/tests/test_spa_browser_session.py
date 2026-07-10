"""Tests for 2-2 config-driven SPA browser session cookies."""

from __future__ import annotations

from diagnosis.g22_replay import (
    playwright_cookies_from_login,
    resolve_spa_browser_session,
    spa_browser_session_mod,
)

SpaBrowserSessionConfig = spa_browser_session_mod().SpaBrowserSessionConfig


def test_resolve_from_explicit_config():
    raw = {
        "auth": {
            "spa_browser_session": {
                "enabled": True,
                "cookies": {
                    "access": "mate_access",
                    "member_id": "mate_uid",
                    "role": "mate_role",
                    "username": "mate_user",
                },
                "login_fields": {
                    "access": "token",
                    "member_id": "userId",
                    "role": "userRole",
                    "username": "@email",
                },
            }
        }
    }
    spa = resolve_spa_browser_session(raw)
    assert spa is not None
    assert spa.cookie_names["access"] == "mate_access"


def test_resolve_disabled_returns_none():
    raw = {"auth": {"spa_browser_session": {"enabled": False, "cookies": {"access": "x"}}}}
    assert resolve_spa_browser_session(raw) is None


def test_resolve_onde_fallback_from_app_name():
    spa = resolve_spa_browser_session({"app_name": "onde-pilot"})
    assert spa is not None
    assert spa.cookie_names["access"] == "onde_access_token"


def test_playwright_cookies_from_login_uses_mapping():
    spa = SpaBrowserSessionConfig.from_mapping(
        {
            "cookies": {
                "access": "mate_access",
                "member_id": "mate_uid",
                "role": "mate_role",
                "username": "mate_user",
            },
            "login_fields": {
                "access": "token",
                "member_id": "userId",
                "role": "userRole",
                "username": "@email",
            },
        }
    )
    assert spa is not None
    cookies = playwright_cookies_from_login(
        {"token": "abc", "userId": 9, "userRole": "ADMIN"},
        email="u@mate.com",
        base_url="http://localhost:3000",
        spa=spa,
    )
    names = {c["name"]: c["value"] for c in cookies}
    assert names["mate_access"] == "abc"
    assert names["mate_uid"] == "9"
    assert names["mate_role"] == "ADMIN"
    assert names["mate_user"] == "u@mate.com"


def test_browser_full_without_spa_degrades_to_dual():
    from inventory.auth_surfaces import build_auth_headers

    session = {
        "email": "u@mate.com",
        "token": "tok",
        "access_token": "tok",
        "refresh_token": "ref",
        "cookie_name": "session",
    }
    headers = build_auth_headers(session, "browser_full", raw_config={"app_name": "mate"})
    assert headers["Authorization"] == "Bearer tok"
    assert "accessToken=tok" in headers["Cookie"]
    assert "onde_" not in headers["Cookie"]
