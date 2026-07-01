"""Auth header helpers for inventory probes."""

from __future__ import annotations

from typing import Any

AUTH_HEADER_NAMES = frozenset(
    {
        "cookie",
        "authorization",
        "x-auth-token",
        "x-access-token",
        "x-api-key",
    }
)


def is_auth_header(name: str) -> bool:
    return (name or "").strip().lower() in AUTH_HEADER_NAMES


def auth_headers(account_auth: dict[str, Any] | None) -> dict[str, str]:
    if not account_auth:
        return {}

    profile = account_auth.get("_auth_profile")
    if profile:
        from inventory.auth_surfaces import build_auth_headers, normalize_session

        session = normalize_session(account_auth)
        overrides = account_auth.get("_auth_overrides")
        cross_from = account_auth.get("_cross_from")
        cross_fields = account_auth.get("_cross_fields")
        return build_auth_headers(
            session,
            str(profile),
            cross_from=cross_from if isinstance(cross_from, dict) else None,
            cross_fields=list(cross_fields) if cross_fields else None,
            overrides=overrides if isinstance(overrides, dict) else None,
        )

    token = str(account_auth.get("token") or account_auth.get("access_token") or "")
    if not token:
        return {}
    if account_auth.get("delivery") == "cookie":
        name = str(account_auth.get("cookie_name") or "accessToken")
        return {"Cookie": f"{name}={token}"}
    if token.startswith("Bearer "):
        return {"Authorization": token}
    return {"Authorization": f"Bearer {token}"}
