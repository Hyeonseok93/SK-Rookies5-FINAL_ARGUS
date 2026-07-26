"""Multi-surface auth header builders (Bearer, API cookies, browser cookie jar)."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

from diagnosis.g22_replay import (
    browser_full_cookie_pairs,
    resolve_spa_browser_session,
    spa_browser_session_mod,
    unwrap_login_payload,
)

SpaBrowserSessionConfig = spa_browser_session_mod().SpaBrowserSessionConfig

AUTH_PROFILES: tuple[str, ...] = (
    "bearer",
    "cookie_access",
    "cookie_refresh",
    "dual",
    "browser_full",
)

GARBAGE_JWT = "invalid.argus.tamper.token"

CROSS_FIELD_KEYS: dict[str, tuple[str, ...]] = {
    "dual": ("bearer", "access_cookie", "refresh_cookie"),
    "browser_full": ("bearer", "access_cookie", "refresh_cookie", "onde_access", "onde_refresh"),
}

# Frontend-only cookies — not API auth; excluded from tamper findings.
NON_API_TAMPER_LABEL_PARTS = (
    "member_id",
    "onde_member_id",
    "onde_username",
    "onde_name",
    "onde_nickname",
    "onde_member_role",
)


def _frontend_only_tamper_labels(spa: SpaBrowserSessionConfig | None) -> tuple[str, ...]:
    if spa is None:
        return NON_API_TAMPER_LABEL_PARTS
    labels = list(NON_API_TAMPER_LABEL_PARTS)
    labels.extend(spa.frontend_only_cookie_names())
    return tuple(dict.fromkeys(labels))


def tamper_label_targets_api_auth(label: str, *, raw_config: dict[str, Any] | None = None) -> bool:
    low = (label or "").lower()
    spa = resolve_spa_browser_session(raw_config)
    return not any(part in low for part in _frontend_only_tamper_labels(spa))


def _frontend_role(role: str) -> str:
    r = str(role or "").strip()
    if r.upper().startswith("ROLE_"):
        return r[5:]
    return r


def normalize_session(session: dict[str, Any]) -> dict[str, Any]:
    """Ensure access_token / refresh_token are populated from legacy fields."""
    out = dict(session)
    access = str(out.get("access_token") or out.get("token") or "")
    refresh = str(out.get("refresh_token") or "")
    if access:
        out["access_token"] = access
        out["token"] = access
    if refresh:
        out["refresh_token"] = refresh
    return out


def session_token_bundle(session: dict[str, Any]) -> dict[str, str]:
    s = normalize_session(session)
    access = str(s.get("access_token") or "")
    refresh = str(s.get("refresh_token") or "")
    email = str(s.get("email") or "")
    member_id = s.get("member_id")
    role = _frontend_role(str(s.get("role") or ""))
    name = str(s.get("name") or "")
    nickname = str(s.get("nickname") or "")
    return {
        "access": access,
        "bearer": access,
        "access_cookie": access,
        "refresh": refresh,
        "email": email,
        "member_id": str(member_id) if member_id is not None else "",
        "role": role,
        "name": name,
        "nickname": nickname,
        "username": email,
    }


def _format_cookie_jar(pairs: list[tuple[str, str]]) -> str:
    return "; ".join(f"{k}={v}" for k, v in pairs if k and v)


def _apply_cross_fields(
    tokens: dict[str, str],
    other: dict[str, Any],
    cross_fields: list[str] | None,
) -> dict[str, str]:
    if not cross_fields:
        return tokens
    other_tokens = session_token_bundle(other)
    out = dict(tokens)
    for field in cross_fields:
        if field == "bearer":
            if other_tokens["access"]:
                out["bearer"] = other_tokens["access"]
        elif field in ("access_cookie", "onde_access"):
            if other_tokens["access"]:
                out["access_cookie"] = other_tokens["access"]
                out["access"] = other_tokens["access"]
        elif field in ("refresh_cookie", "onde_refresh"):
            if other_tokens["refresh"]:
                out["refresh"] = other_tokens["refresh"]
        elif field == "onde_member_id":
            if other_tokens["member_id"]:
                out["member_id"] = other_tokens["member_id"]
        elif field == "onde_member_role":
            if other_tokens["role"]:
                out["role"] = other_tokens["role"]
        elif field == "onde_username":
            if other_tokens["username"]:
                out["username"] = other_tokens["username"]
    return out


def _apply_overrides(tokens: dict[str, str], overrides: dict[str, Any]) -> dict[str, str]:
    out = dict(tokens)
    if overrides.get("_omit_bearer"):
        out["bearer"] = ""
    if overrides.get("_omit_cookies"):
        out["access_cookie"] = ""
        out["access"] = ""
        out["refresh"] = ""
    mapping = {
        "bearer_token": "bearer",
        "bearer": "bearer",
        "access_token": "access",
        "access_cookie": "access_cookie",
        "token": "access",
        "refresh_token": "refresh",
        "member_id": "member_id",
        "role": "role",
        "username": "username",
        "name": "name",
        "nickname": "nickname",
    }
    for key, target in mapping.items():
        if key in overrides and overrides[key] is not None:
            val = str(overrides[key])
            out[target] = val
            if target in ("access", "access_cookie") and key in ("access_token", "token", "access_cookie"):
                if key != "access_cookie":
                    out["access"] = val
                if key != "access_token" and key != "token":
                    out["access_cookie"] = val
    if "access_token" in overrides or "token" in overrides:
        val = str(overrides.get("access_token") or overrides.get("token") or "")
        if val:
            out["access"] = val
            if "access_cookie" not in overrides:
                out["access_cookie"] = val
            if "bearer_token" not in overrides and "bearer" not in overrides:
                out["bearer"] = val
    return out


def build_auth_headers(
    session: dict[str, Any],
    profile: str,
    *,
    cross_from: dict[str, Any] | None = None,
    cross_fields: list[str] | None = None,
    overrides: dict[str, Any] | None = None,
    raw_config: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Build probe HTTP auth headers for a given surface profile."""
    if profile not in AUTH_PROFILES:
        profile = "cookie_access"

    tokens = session_token_bundle(session)
    if cross_from is not None:
        tokens = _apply_cross_fields(tokens, cross_from, cross_fields)
    if overrides:
        tokens = _apply_overrides(tokens, overrides)

    access = tokens["access"]
    access_cookie = tokens.get("access_cookie") or access
    bearer = tokens.get("bearer") or access
    refresh = tokens["refresh"]

    if profile == "bearer":
        if not bearer:
            return {}
        return {"Authorization": bearer if bearer.startswith("Bearer ") else f"Bearer {bearer}"}

    if profile == "cookie_access":
        if not access_cookie:
            return {}
        name = str(session.get("cookie_name") or "accessToken")
        return {"Cookie": f"{name}={access_cookie}"}

    if profile == "cookie_refresh":
        if not refresh:
            return {}
        return {"Cookie": f"refreshToken={refresh}"}

    if profile == "dual":
        headers: dict[str, str] = {}
        cookie_parts: list[tuple[str, str]] = []
        if access_cookie:
            cookie_parts.append(("accessToken", access_cookie))
        if refresh:
            cookie_parts.append(("refreshToken", refresh))
        if cookie_parts:
            headers["Cookie"] = _format_cookie_jar(cookie_parts)
        if bearer:
            headers["Authorization"] = bearer if bearer.startswith("Bearer ") else f"Bearer {bearer}"
        return headers

    # browser_full — API cookies + optional SPA browser jar (config-driven)
    spa = resolve_spa_browser_session(raw_config)
    if spa is None:
        return build_auth_headers(
            session,
            "dual",
            cross_from=cross_from,
            cross_fields=cross_fields,
            overrides=overrides,
            raw_config=raw_config,
        )

    cookie_parts = browser_full_cookie_pairs(tokens, spa=spa)
    headers = {}
    if cookie_parts:
        headers["Cookie"] = _format_cookie_jar(cookie_parts)
    if bearer:
        headers["Authorization"] = bearer if bearer.startswith("Bearer ") else f"Bearer {bearer}"
    return headers


def enrich_auth_session(
    session: dict[str, Any],
    resp: Any,
    *,
    auth_cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach access/refresh tokens and member fields from login response."""
    out = dict(session)
    payload: dict[str, Any] = {}
    try:
        payload = unwrap_login_payload(resp.json())
    except Exception:
        payload = {}

    cookie_access = resp.cookies.get("accessToken") if hasattr(resp, "cookies") else None
    cookie_refresh = resp.cookies.get("refreshToken") if hasattr(resp, "cookies") else None

    access = (
        out.get("token")
        or cookie_access
        or payload.get("accessToken")
    )
    refresh = cookie_refresh or payload.get("refreshToken")

    if access:
        out["access_token"] = str(access)
        out["token"] = str(access)
    if refresh:
        out["refresh_token"] = str(refresh)

    for key in ("memberId", "role", "name", "nickname", "username"):
        if payload.get(key) is not None:
            out_key = "member_id" if key == "memberId" else key
            out[out_key] = payload[key]

    if out.get("email") and not out.get("username"):
        out["username"] = out["email"]

    if auth_cfg and not out.get("cookie_name"):
        out["cookie_name"] = auth_cfg.get("cookie_name", "accessToken")
    if auth_cfg and not out.get("delivery"):
        out["delivery"] = auth_cfg.get("delivery", "cookie")

    return out


def _jwt_tamper_tokens(token: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = [("garbage", GARBAGE_JWT)]
    if not token:
        return variants
    if token.count(".") == 2:
        parts = token.split(".")
        variants.append(("truncated", f"{parts[0]}.{parts[1]}."))
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload))
            if isinstance(data, dict):
                mutated = dict(data)
                role = str(mutated.get("role") or "")
                if "ADMIN" in role.upper():
                    mutated["role"] = "ROLE_USER"
                else:
                    mutated["role"] = "ROLE_ADMIN"
                raw = json.dumps(mutated, separators=(",", ":")).encode()
                b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
                variants.append(("jwt_payload_mutated", f"{parts[0]}.{b64}.{parts[2]}"))
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            pass
    else:
        variants.append(("bitflip", token[:-1] + ("x" if token[-1:] != "x" else "y")))
    return variants


def tamper_surface_variants(
    session: dict[str, Any],
    profile: str,
    *,
    other_sessions: list[dict[str, Any]] | None = None,
    include_partial_cross: bool = True,
) -> list[tuple[str, dict[str, Any]]]:
    """Return (label, auth_ctx) tamper variants for one auth surface profile."""
    s = normalize_session(session)
    variants: list[tuple[str, dict[str, Any]]] = []

    def ctx(**extra: Any) -> dict[str, Any]:
        base = {**s, "_auth_profile": profile}
        base.update(extra)
        return base

    access = str(s.get("access_token") or "")
    refresh = str(s.get("refresh_token") or "")

    if profile == "bearer":
        variants.append(("empty_bearer", ctx(_auth_overrides={"_omit_bearer": True})))
        for suffix, tok in _jwt_tamper_tokens(access):
            variants.append((f"bearer_{suffix}", ctx(_auth_overrides={"bearer_token": tok})))
        return variants

    if profile == "cookie_access":
        variants.append(("empty_cookie", None))
        for suffix, tok in _jwt_tamper_tokens(access):
            variants.append((f"access_cookie_{suffix}", ctx(_auth_overrides={"access_token": tok})))
        return variants

    if profile == "cookie_refresh":
        if not refresh:
            variants.append(("empty_refresh", None))
            return variants
        variants.append(("empty_refresh", ctx(_auth_overrides={"refresh_token": ""})))
        for suffix, tok in _jwt_tamper_tokens(refresh):
            variants.append((f"refresh_cookie_{suffix}", ctx(_auth_overrides={"refresh_token": tok})))
        return variants

    if profile in ("dual", "browser_full"):
        variants.append((f"{profile}_empty_all", None))
        for suffix, tok in _jwt_tamper_tokens(access):
            variants.append(
                (
                    f"{profile}_bearer_{suffix}",
                    ctx(_auth_overrides={"bearer_token": tok}),
                )
            )
            variants.append(
                (
                    f"{profile}_access_cookie_{suffix}",
                    ctx(_auth_overrides={"access_cookie": tok}),
                )
            )
        if refresh:
            for suffix, tok in _jwt_tamper_tokens(refresh):
                variants.append(
                    (
                        f"{profile}_refresh_cookie_{suffix}",
                        ctx(_auth_overrides={"refresh_token": tok}),
                    )
                )
        if profile == "browser_full" and s.get("member_id") is not None:
            pass  # onde_member_id is frontend-only — not an API auth vector

        if include_partial_cross and other_sessions:
            for other in other_sessions:
                if session_key(session) == session_key(other):
                    continue
                for field in CROSS_FIELD_KEYS.get(profile, ()):
                    variants.append(
                        (
                            f"{profile}_cross_{field}_only",
                            ctx(_cross_from=other, _cross_fields=[field]),
                        )
                    )
        return variants

    return variants


def session_key(session: dict[str, Any]) -> tuple[str, str]:
    return (
        str(session.get("email") or "").lower(),
        str(session.get("login_url") or "").rstrip("/"),
    )


def resolve_auth_profiles(raw: list[str] | None) -> list[str]:
    if not raw:
        return list(AUTH_PROFILES)
    out: list[str] = []
    for item in raw:
        p = str(item).strip().lower()
        if p in AUTH_PROFILES and p not in out:
            out.append(p)
    return out or list(AUTH_PROFILES)


def tamper_isolation_profile(combo_profile: str, label: str) -> str | None:
    """When a combo profile (dual/browser) returns 200, re-test on a single surface only."""
    if combo_profile not in ("dual", "browser_full"):
        return None
    if (
        "_access_cookie_" in label
        or label.endswith("_cross_access_cookie_only")
        or label.endswith("_cross_onde_access_only")
    ):
        return "cookie_access"
    if (
        "_refresh_cookie_" in label
        or label.endswith("_cross_refresh_cookie_only")
        or label.endswith("_cross_onde_refresh_only")
    ):
        return "cookie_refresh"
    if "_bearer_" in label or label.endswith("_cross_bearer_only"):
        return "bearer"
    return None


def build_isolated_confirm_ctx(tampered: dict[str, Any], label: str) -> dict[str, Any] | None:
    """Build follow-up probe that sends only the tampered auth surface (no Bearer+cookie mix)."""
    if tampered is None:
        return None
    profile = str(tampered.get("_auth_profile") or "")
    isolated = tamper_isolation_profile(profile, label)
    if not isolated:
        return None
    ctx = dict(tampered)
    ctx["_auth_profile"] = isolated
    cross_fields = ctx.get("_cross_fields")
    if cross_fields and isolated == "bearer":
        ctx["_cross_fields"] = ["bearer"]
    elif cross_fields and isolated == "cookie_access":
        ctx["_cross_fields"] = ["access_cookie"]
    elif cross_fields and isolated == "cookie_refresh":
        ctx["_cross_fields"] = ["refresh_cookie"]
    return ctx
