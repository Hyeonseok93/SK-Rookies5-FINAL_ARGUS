"""2-2 SPA browser session cookies — module asset + optional config overrides.

Resolution order:
  1) config ``auth.spa_browser_session``
  2) config ``frontend.cookies`` (same shape as screenshot 5-2)
  3) ``modules/2-2/replay/assets/spa_browser_session.yaml``
  4) best-effort infer from login JSON keys (no fixed app cookie names)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx
import yaml

_ASSET_PATH = Path(__file__).resolve().parent / "assets" / "spa_browser_session.yaml"

_DEFAULT_LOGIN_FIELDS: dict[str, str] = {
    "access": "accessToken",
    "refresh": "refreshToken",
    "member_id": "memberId",
    "role": "role",
    "username": "@email",
    "name": "name",
    "nickname": "nickname",
}

# Common login JSON aliases → logical cookie keys (app-agnostic).
_LOGIN_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "access": ("accessToken", "access_token", "token", "jwt", "idToken"),
    "refresh": ("refreshToken", "refresh_token"),
    "member_id": ("memberId", "member_id", "userId", "user_id", "id"),
    "role": ("role", "userRole", "user_role", "authority"),
    "username": ("username", "email", "userName", "loginId"),
    "name": ("name", "displayName", "fullName"),
    "nickname": ("nickname", "nickName"),
}

_DEFAULT_REQUIRED = ("access", "member_id", "role", "username")

# Legacy alias for inventory/tests. Prefer module asset / resolve_spa_browser_session.
ONDE_COOKIE_NAMES = {
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
    required: tuple[str, ...] = _DEFAULT_REQUIRED

    @classmethod
    def onde_default(cls) -> SpaBrowserSessionConfig:
        """Load 2-2 module asset (legacy name kept for tests)."""
        asset = _load_module_asset()
        if asset is not None:
            return asset
        return cls(cookie_names=dict(ONDE_COOKIE_NAMES))

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> SpaBrowserSessionConfig | None:
        cookies = dict(raw.get("cookies") or raw.get("cookie_names") or raw.get("names") or {})
        if not cookies:
            return None
        login_fields = dict(_DEFAULT_LOGIN_FIELDS)
        login_fields.update(dict(raw.get("login_fields") or {}))
        required_raw = raw.get("required")
        required = tuple(required_raw) if required_raw else _DEFAULT_REQUIRED
        return cls(
            cookie_names=cookies,
            login_fields=login_fields,
            api_access_cookie=str(raw.get("api_access_cookie") or "accessToken"),
            api_refresh_cookie=str(raw.get("api_refresh_cookie") or "refreshToken"),
            required=tuple(str(x) for x in required),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookie_names": dict(self.cookie_names),
            "login_fields": dict(self.login_fields),
            "api_access_cookie": self.api_access_cookie,
            "api_refresh_cookie": self.api_refresh_cookie,
            "required": list(self.required),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> SpaBrowserSessionConfig | None:
        if not isinstance(raw, dict) or not raw.get("cookie_names"):
            return None
        required = raw.get("required") or _DEFAULT_REQUIRED
        return cls(
            cookie_names=dict(raw["cookie_names"]),
            login_fields=dict(raw.get("login_fields") or _DEFAULT_LOGIN_FIELDS),
            api_access_cookie=str(raw.get("api_access_cookie") or "accessToken"),
            api_refresh_cookie=str(raw.get("api_refresh_cookie") or "refreshToken"),
            required=tuple(str(x) for x in required),
        )

    def frontend_only_cookie_names(self) -> tuple[str, ...]:
        names: list[str] = []
        for key in ("member_id", "role", "username", "name", "nickname"):
            name = self.cookie_names.get(key)
            if name:
                names.append(name)
        return tuple(names)


def _load_module_asset() -> SpaBrowserSessionConfig | None:
    if not _ASSET_PATH.is_file():
        return None
    try:
        raw = yaml.safe_load(_ASSET_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    if isinstance(raw, dict) and raw.get("enabled") is False:
        return None
    return SpaBrowserSessionConfig.from_mapping(raw if isinstance(raw, dict) else {})


def _from_frontend_cookies(raw_config: dict[str, Any] | None) -> SpaBrowserSessionConfig | None:
    """Reuse config ``frontend.cookies`` (same section screenshot 5-2 reads)."""
    front = dict((raw_config or {}).get("frontend") or {})
    cookies = dict(front.get("cookies") or {})
    names = dict(cookies.get("names") or {})
    if not names:
        return None
    block = {
        "cookies": names,
        "required": cookies.get("required") or list(_DEFAULT_REQUIRED),
        "login_fields": dict(front.get("login_fields") or {}),
        "api_access_cookie": front.get("api_access_cookie") or "accessToken",
        "api_refresh_cookie": front.get("api_refresh_cookie") or "refreshToken",
    }
    return SpaBrowserSessionConfig.from_mapping(block)


def _looks_like_onde_app(raw: dict[str, Any]) -> bool:
    app = str(raw.get("app_name") or "").lower()
    if "onde" in app:
        return True
    inv = dict(raw.get("inventory") or {})
    md = dict(inv.get("markdown") or {})
    path = str(md.get("path") or "").lower()
    return "onde" in path


def resolve_spa_browser_session(
    raw_config: dict[str, Any] | None,
    *,
    prefer_module_asset: bool = False,
) -> SpaBrowserSessionConfig | None:
    """Resolve SPA cookie mapping without requiring global config.yaml edits.

    Order: auth.spa_browser_session → frontend.cookies → 2-2 module asset
    (asset only when ``prefer_module_asset`` or the target looks like Onde).
    """
    raw = raw_config or {}
    auth = dict(raw.get("auth") or {})
    block = auth.get("spa_browser_session") or auth.get("spa_browser_cookies")
    if isinstance(block, dict):
        if block.get("enabled") is False:
            return None
        parsed = SpaBrowserSessionConfig.from_mapping(block)
        if parsed is not None:
            return parsed

    from_front = _from_frontend_cookies(raw)
    if from_front is not None:
        return from_front

    if prefer_module_asset or _looks_like_onde_app(raw):
        return _load_module_asset()
    return None


def unwrap_login_payload(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("data"), dict) and any(
        k in data["data"] for k in ("accessToken", "access_token", "token", "memberId", "userId")
    ):
        return dict(data["data"])
    if any(k in data for k in ("accessToken", "access_token", "token", "memberId", "userId")):
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
        # Dynamic fallback: try common aliases for this logical field.
        for alias in _LOGIN_FIELD_ALIASES.get(field_key, ()):
            if login.get(alias) is not None:
                return str(login.get(alias))
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


def infer_spa_from_login(
    login: dict[str, Any],
    *,
    email: str,
    cookie_prefix: str = "session",
) -> SpaBrowserSessionConfig | None:
    """Best-effort mapping when no config/asset cookie names exist.

    Builds cookie names as ``{prefix}_{logical_key}`` from whatever login fields
    are present (accessToken/memberId/…). Prefer explicit asset/config mapping.
    """
    if not login:
        return None
    cookie_names: dict[str, str] = {}
    login_fields: dict[str, str] = dict(_DEFAULT_LOGIN_FIELDS)
    for logical, aliases in _LOGIN_FIELD_ALIASES.items():
        for alias in aliases:
            if login.get(alias) is not None:
                cookie_names[logical] = f"{cookie_prefix}_{logical}"
                login_fields[logical] = alias
                break
    if email and "username" not in cookie_names:
        cookie_names["username"] = f"{cookie_prefix}_username"
        login_fields["username"] = "@email"
    if "access" not in cookie_names:
        return None
    return SpaBrowserSessionConfig(
        cookie_names=cookie_names,
        login_fields=login_fields,
        required=tuple(k for k in _DEFAULT_REQUIRED if k in cookie_names) or ("access",),
    )


def playwright_cookies_from_login(
    login: dict[str, Any],
    *,
    email: str,
    base_url: str,
    spa: SpaBrowserSessionConfig | None = None,
) -> list[dict[str, Any]]:
    """Build Playwright cookies for a configured (or inferred) SPA session."""
    if spa is None:
        spa = infer_spa_from_login(login, email=email)
    if spa is None:
        return []

    values = session_values_from_login(login, email=email, spa=spa)
    for key in spa.required:
        if not values.get(key):
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
        # perform_login lives in the 2-2 module — default to module asset mapping.
        spa = resolve_spa_browser_session(raw_config, prefer_module_asset=True)

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
    if spa is None:
        spa = infer_spa_from_login(login_payload, email=email)
    browser_cookies = playwright_cookies_from_login(
        login_payload,
        email=email,
        base_url=cookie_base,
        spa=spa,
    )
    return api_headers, browser_cookies
