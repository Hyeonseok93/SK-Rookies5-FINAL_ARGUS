"""Map API login responses to browser cookies for SPA replay."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import httpx

# Onde frontend authCookies.ts — RequireAuth checks member_id + role + username.
ONDE_COOKIE_NAMES = {
    "access": "onde_access_token",
    "refresh": "onde_refresh_token",
    "member_id": "onde_member_id",
    "role": "onde_member_role",
    "username": "onde_username",
    "name": "onde_name",
    "nickname": "onde_nickname",
}


def _unwrap_login_payload(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("data"), dict) and (
        "accessToken" in data["data"] or "memberId" in data["data"]
    ):
        return dict(data["data"])
    if "accessToken" in data or "memberId" in data:
        return dict(data)
    return {}


def _cookie_domain(base_url: str) -> str:
    parsed = urlparse(base_url)
    return parsed.hostname or "localhost"


def playwright_cookies_from_login(
    login: dict[str, Any],
    *,
    email: str,
    base_url: str,
) -> list[dict[str, Any]]:
    """Build Playwright cookies that satisfy Onde RequireAuth.hasAuthSession()."""
    domain = _cookie_domain(base_url)
    access = str(login.get("accessToken") or "")
    refresh = str(login.get("refreshToken") or "")
    member_id = login.get("memberId")
    role = str(login.get("role") or "")
    username = email or str(login.get("username") or "")

    if not access or member_id is None or not role or not username:
        return []

    expires = login.get("expiresIn")
    max_age = int(expires) if expires else 60 * 60 * 24 * 7
    expires_at = int(time.time()) + max_age

    def make(name: str, value: str) -> dict[str, Any]:
        return {
            "name": name,
            "value": value,
            "domain": domain,
            "path": "/",
            "sameSite": "Lax",
            "expires": expires_at,
        }

    cookies = [
        make(ONDE_COOKIE_NAMES["access"], access),
        make(ONDE_COOKIE_NAMES["member_id"], str(member_id)),
        make(ONDE_COOKIE_NAMES["role"], role),
        make(ONDE_COOKIE_NAMES["username"], username),
    ]
    if refresh:
        cookies.append(make(ONDE_COOKIE_NAMES["refresh"], refresh))
    return cookies


def perform_login(
    client: httpx.Client,
    *,
    login_url: str,
    email: str,
    password: str,
    id_field: str,
    pw_field: str,
    delivery: str,
    cookie_name: str,
    token_field: str = "cookie.accessToken",
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Login once; return httpx auth headers + Playwright browser cookies."""
    if not login_url or not email:
        return {}, []

    resp = client.post(login_url, json={id_field: email, pw_field: password})
    login_payload: dict[str, Any] = {}
    try:
        login_payload = _unwrap_login_payload(resp.json())
    except Exception:
        login_payload = {}

    api_headers: dict[str, str] = {}
    if delivery == "cookie":
        for cookie in resp.cookies.jar:
            if cookie.name == cookie_name or cookie_name in cookie.name:
                api_headers = {"Cookie": f"{cookie.name}={cookie.value}"}
                break
        if not api_headers and login_payload.get("accessToken"):
            api_headers = {"Cookie": f"{cookie_name}={login_payload['accessToken']}"}
        elif not api_headers and str(token_field).startswith("cookie."):
            cname = token_field.split(".", 1)[1]
            try:
                parts = token_field.split(".")
                cur: Any = resp.json()
                for p in parts:
                    cur = cur[p]
                api_headers = {"Cookie": f"{cname}={cur}"}
            except Exception:
                pass
    else:
        try:
            data = resp.json()
            parts = token_field.split(".")
            cur: Any = data
            for p in parts:
                cur = cur[p]
            tok = str(cur)
            if not tok.startswith("Bearer "):
                tok = f"Bearer {tok}"
            api_headers = {"Authorization": tok}
        except Exception:
            pass

    browser_cookies = playwright_cookies_from_login(login_payload, email=email, base_url=login_url)
    return api_headers, browser_cookies
