"""2-2 config-driven SPA browser session cookies (Playwright + browser_full)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlparse

import httpx

_DEFAULT_LOGIN_FIELDS: dict[str, str] = {
    "access": "accessToken",
    "refresh": "refreshToken",
    "member_id": "memberId",
    "role": "role",
    "username": "@email",
    "name": "name",
    "nickname": "nickname",
}

_ONDE_COOKIE_NAMES: dict[str, str] = {
    "access": "onde_access_token",
    "refresh": "onde_refresh_token",
    "member_id": "onde_member_id",
    "role": "onde_member_role",
    "username": "onde_username",
    "name": "onde_name",
    "nickname": "onde_nickname",
}


@dataclass(frozen=True)
class SpaBrowserSessionConfig:
    """Map login API fields → browser cookie names for a target SPA."""

    cookie_names: dict[str, str]
    login_fields: dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_LOGIN_FIELDS))
    api_access_cookie: str = "accessToken"
    api_refresh_cookie: str = "refreshToken"

    @classmethod
    def onde_default(cls) -> SpaBrowserSessionConfig:
        return cls(cookie_names=dict(_ONDE_COOKIE_NAMES))

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> SpaBrowserSessionConfig | None:
        cookies = dict(raw.get("cookies") or raw.get("cookie_names") or {})
        if not cookies:
            return None
        login_fields = dict(_DEFAULT_LOGIN_FIELDS)
        login_fields.update(dict(raw.get("login_fields") or {}))
        return cls(
            cookie_names=cookies,
            login_fields=login_fields,
            api_access_cookie=str(raw.get("api_access_cookie") or "accessToken"),
            api_refresh_cookie=str(raw.get("api_refresh_cookie") or "refreshToken"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookie_names": dict(self.cookie_names),
            "login_fields": dict(self.login_fields),
            "api_access_cookie": self.api_access_cookie,
            "api_refresh_cookie": self.api_refresh_cookie,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> SpaBrowserSessionConfig | None:
        if not isinstance(raw, dict) or not raw.get("cookie_names"):
            return None
        return cls(
            cookie_names=dict(raw["cookie_names"]),
            login_fields=dict(raw.get("login_fields") or _DEFAULT_LOGIN_FIELDS),
            api_access_cookie=str(raw.get("api_access_cookie") or "accessToken"),
            api_refresh_cookie=str(raw.get("api_refresh_cookie") or "refreshToken"),
        )

    def frontend_only_cookie_names(self) -> tuple[str, ...]:
        names: list[str] = []
        for key in ("member_id", "role", "username", "name", "nickname"):
            name = self.cookie_names.get(key)
            if name:
                names.append(name)
        return tuple(names)


def resolve_spa_browser_session(raw_config: dict[str, Any] | None) -> SpaBrowserSessionConfig | None:
    raw = raw_config or {}
    auth = dict(raw.get("auth") or {})
    block = auth.get("spa_browser_session") or auth.get("spa_browser_cookies")
    if isinstance(block, dict):
        if block.get("enabled") is False:
            return None
        parsed = SpaBrowserSessionConfig.from_mapping(block)
        if parsed is not None:
            return parsed
    app_name = str(raw.get("app_name") or "").lower()
    if "onde" in app_name:
        return SpaBrowserSessionConfig.onde_default()
    return None


# Backward-compatible alias used by older imports/tests.
ONDE_COOKIE_NAMES = dict(_ONDE_COOKIE_NAMES)


def unwrap_login_payload(data: Any) -> dict[str, Any]:
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


def _login_value(
    login: dict[str, Any],
    *,
    field_key: str,
    login_fields: dict[str, str],
    email: str,
) -> str:
    source = login_fields.get(field_key, field_key)
    if source == "@email":
        return email
    if source.startswith("@"):
        return str(login.get(source[1:]) or "")
    value = login.get(source)
    if value is None:
        return ""
    return str(value)


def session_values_from_login(
    login: dict[str, Any],
    *,
    email: str,
    spa: SpaBrowserSessionConfig,
) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in spa.cookie_names:
        values[key] = _login_value(login, field_key=key, login_fields=spa.login_fields, email=email)
    return values


def playwright_cookies_from_login(
    login: dict[str, Any],
    *,
    email: str,
    base_url: str,
    spa: SpaBrowserSessionConfig | None = None,
) -> list[dict[str, Any]]:
    """Build Playwright cookies for a configured SPA session."""
    if spa is None:
        return []

    values = session_values_from_login(login, email=email, spa=spa)
    access = values.get("access", "")
    member_id = values.get("member_id", "")
    role = values.get("role", "")
    username = values.get("username", "")
    if not access or not member_id or not role or not username:
        return []

    domain = _cookie_domain(base_url)
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

    cookies: list[dict[str, Any]] = []
    for key, cookie_name in spa.cookie_names.items():
        value = values.get(key, "")
        if value:
            cookies.append(make(cookie_name, value))
    return cookies


def browser_full_cookie_pairs(
    tokens: dict[str, str],
    *,
    spa: SpaBrowserSessionConfig,
) -> list[tuple[str, str]]:
    """Cookie jar pairs for browser_full auth profile."""
    pairs: list[tuple[str, str]] = []
    access = tokens.get("access_cookie") or tokens.get("access") or ""
    refresh = tokens.get("refresh") or ""
    if access:
        pairs.append((spa.api_access_cookie, access))
        spa_access = spa.cookie_names.get("access")
        if spa_access and spa_access != spa.api_access_cookie:
            pairs.append((spa_access, access))
    if refresh:
        pairs.append((spa.api_refresh_cookie, refresh))
        spa_refresh = spa.cookie_names.get("refresh")
        if spa_refresh and spa_refresh != spa.api_refresh_cookie:
            pairs.append((spa_refresh, refresh))
    if tokens.get("member_id") and spa.cookie_names.get("member_id"):
        pairs.append((spa.cookie_names["member_id"], tokens["member_id"]))
    if tokens.get("role") and spa.cookie_names.get("role"):
        pairs.append((spa.cookie_names["role"], tokens["role"]))
    if tokens.get("username") and spa.cookie_names.get("username"):
        pairs.append((spa.cookie_names["username"], quote(tokens["username"], safe="@")))
    if tokens.get("name") and spa.cookie_names.get("name"):
        pairs.append((spa.cookie_names["name"], tokens["name"]))
    if tokens.get("nickname") and spa.cookie_names.get("nickname"):
        pairs.append((spa.cookie_names["nickname"], tokens["nickname"]))
    return pairs


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
    spa: SpaBrowserSessionConfig | None = None,
    raw_config: dict[str, Any] | None = None,
    frontend_base_url: str | None = None,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Login once; return httpx auth headers + optional Playwright browser cookies."""
    if not login_url or not email:
        return {}, []

    if spa is None:
        spa = resolve_spa_browser_session(raw_config)

    resp = client.post(login_url, json={id_field: email, pw_field: password})
    login_payload: dict[str, Any] = {}
    try:
        login_payload = unwrap_login_payload(resp.json())
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

    cookie_base = frontend_base_url or login_url
    browser_cookies = playwright_cookies_from_login(
        login_payload,
        email=email,
        base_url=cookie_base,
        spa=spa,
    )
    return api_headers, browser_cookies
