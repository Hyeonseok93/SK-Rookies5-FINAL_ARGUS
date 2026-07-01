"""Tests for multi-surface auth header builders."""

from __future__ import annotations

from inventory.auth_surfaces import (
    AUTH_PROFILES,
    build_auth_headers,
    normalize_session,
    session_token_bundle,
    tamper_surface_variants,
)


def _sample_session() -> dict:
    return {
        "email": "yerin@travel.com",
        "token": "acc.jwt.token",
        "access_token": "acc.jwt.token",
        "refresh_token": "ref.jwt.token",
        "member_id": 1,
        "role": "ROLE_USER",
        "name": "testa",
        "nickname": "testata",
        "cookie_name": "accessToken",
    }


def test_build_bearer_only():
    headers = build_auth_headers(_sample_session(), "bearer")
    assert headers == {"Authorization": "Bearer acc.jwt.token"}
    assert "Cookie" not in headers


def test_build_cookie_access_only():
    headers = build_auth_headers(_sample_session(), "cookie_access")
    assert headers == {"Cookie": "accessToken=acc.jwt.token"}


def test_build_cookie_refresh_only():
    headers = build_auth_headers(_sample_session(), "cookie_refresh")
    assert headers == {"Cookie": "refreshToken=ref.jwt.token"}


def test_build_dual_includes_bearer_and_cookies():
    headers = build_auth_headers(_sample_session(), "dual")
    assert headers["Authorization"] == "Bearer acc.jwt.token"
    assert "accessToken=acc.jwt.token" in headers["Cookie"]
    assert "refreshToken=ref.jwt.token" in headers["Cookie"]


def test_build_browser_full_matches_spa_shape():
    headers = build_auth_headers(_sample_session(), "browser_full")
    cookie = headers["Cookie"]
    assert "accessToken=acc.jwt.token" in cookie
    assert "onde_access_token=acc.jwt.token" in cookie
    assert "refreshToken=ref.jwt.token" in cookie
    assert "onde_refresh_token=ref.jwt.token" in cookie
    assert "onde_member_id=1" in cookie
    assert "onde_member_role=USER" in cookie
    assert "onde_username=yerin@travel.com" in cookie
    assert headers["Authorization"] == "Bearer acc.jwt.token"


def test_dual_bearer_tamper_keeps_valid_cookies():
    session = _sample_session()
    variants = tamper_surface_variants(session, "dual", include_partial_cross=False)
    label, ctx = next(v for v in variants if v[0] == "dual_bearer_garbage")
    assert label
    headers = build_auth_headers(ctx, "dual", overrides=ctx.get("_auth_overrides"))
    assert headers["Authorization"] == "Bearer invalid.argus.tamper.token"
    assert "accessToken=acc.jwt.token" in headers["Cookie"]


def test_dual_access_cookie_tamper_keeps_valid_bearer():
    session = _sample_session()
    variants = tamper_surface_variants(session, "dual", include_partial_cross=False)
    label, ctx = next(v for v in variants if v[0] == "dual_access_cookie_garbage")
    headers = build_auth_headers(ctx, "dual", overrides=ctx.get("_auth_overrides"))
    assert headers["Authorization"] == "Bearer acc.jwt.token"
    assert "accessToken=invalid.argus.tamper.token" in headers["Cookie"]


def test_partial_cross_bearer_only():
    owner = _sample_session()
    other = {
        **_sample_session(),
        "email": "ondecar@travel.com",
        "access_token": "other.jwt.token",
        "token": "other.jwt.token",
        "member_id": 2,
    }
    ctx = {
        **owner,
        "_auth_profile": "browser_full",
        "_cross_from": other,
        "_cross_fields": ["bearer"],
    }
    headers = build_auth_headers(
        ctx,
        "browser_full",
        cross_from=ctx["_cross_from"],
        cross_fields=ctx["_cross_fields"],
    )
    assert headers["Authorization"] == "Bearer other.jwt.token"
    assert "accessToken=acc.jwt.token" in headers["Cookie"]
    assert "onde_access_token=acc.jwt.token" in headers["Cookie"]


def test_normalize_session_from_legacy_token():
    bundle = session_token_bundle({"email": "a@x.com", "token": "legacy"})
    assert bundle["access"] == "legacy"


def test_tamper_isolation_profile_for_dual_access_cookie():
    from inventory.auth_surfaces import build_isolated_confirm_ctx, tamper_isolation_profile

    assert tamper_isolation_profile("dual", "dual_access_cookie_garbage") == "cookie_access"
    assert tamper_isolation_profile("browser_full", "browser_full_bearer_garbage") == "bearer"
    assert tamper_isolation_profile("cookie_access", "access_cookie_garbage") is None

    owner = _sample_session()
    tampered = {
        **owner,
        "_auth_profile": "dual",
        "_auth_overrides": {"access_cookie": "invalid.argus.tamper.token"},
    }
    confirm = build_isolated_confirm_ctx(tampered, "dual_access_cookie_garbage")
    assert confirm is not None
    assert confirm["_auth_profile"] == "cookie_access"
    headers = build_auth_headers(confirm, "cookie_access", overrides=confirm.get("_auth_overrides"))
    assert "Authorization" not in headers
    assert "invalid.argus.tamper.token" in headers["Cookie"]


def test_all_profiles_defined():
    assert len(AUTH_PROFILES) == 5
