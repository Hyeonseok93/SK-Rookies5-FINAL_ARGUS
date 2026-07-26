"""Shared login → httpx auth headers for diagnosis probes (2-2 pattern)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.auth_probe_service import resolve_account_auths
from app.services.test_accounts_service import DATA_DIR, load_test_accounts
from inventory.auth_util import auth_headers


def all_account_auths_with_meta(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
    refresh: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = raw_config or {}
    auth_cfg = raw.get("auth") or {}
    accounts = load_test_accounts().get("accounts") or []
    if not accounts:
        return [], {"source": "none", "sessions": 0}

    return resolve_account_auths(
        auth_cfg,
        accounts,
        data_dir=data_dir or DATA_DIR,
        refresh=refresh,
    )


def all_account_auths(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
    refresh: bool = False,
) -> list[dict[str, Any]]:
    """Test-account sessions — verify cache first, then fast targeted live login."""
    sessions, _meta = all_account_auths_with_meta(
        raw_config, data_dir=data_dir, refresh=refresh
    )
    return sessions


def primary_account_auth(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
) -> dict[str, Any] | None:
    """First successful test-account login, or None."""
    sessions = all_account_auths(raw_config, data_dir=data_dir)
    return sessions[0] if sessions else None


def session_auth_mode(session: dict[str, Any]) -> str:
    """Distinct auth_mode for findings when multiple login sessions are probed."""
    email = str(session.get("email") or "account")
    label = str(session.get("login_label") or "login")
    return f"authenticated:{email}:{label}"


def session_probe_tag(session: dict[str, Any]) -> str:
    """Human-readable authenticated pass label."""
    email = str(session.get("email") or "account")
    label = str(session.get("login_label") or "login")
    return f"{email} · {label}"


def probe_request_headers(account_auth: dict[str, Any] | None) -> dict[str, str]:
    return auth_headers(account_auth)
