"""Targets and helpers for guideline 4-2."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.services.auth_probe_service import (
    configured_login_entries,
    login_urls_for_account,
    valid_login_accounts,
)
from app.services.test_accounts_service import load_test_accounts
from app.services.zap_util import probe_url
from diagnosis.probe_auth import all_account_auths_with_meta
from diagnosis.replay.normalize import collect_probe_base_urls, filter_endpoints_by_probe_bases
from diagnosis.result import DiagnosisFinding
from inventory.schema import ApiTree, build_full_url
from inventory.load import load_api_tree

LOGOUT_PATH_RE = re.compile(r"(?i)(/(auth/)?(logout|sign-?out)(/|$)|/logout$)")
LOGIN_PATH_RE = re.compile(r"(?i)(/(auth/)?(login|sign-?in)(/|$)|/login$)")



def load_login_report(data_dir: Path, raw_config: dict[str, Any] | None) -> dict[str, Any] | None:
    from diagnosis.replay.normalize import filter_login_entry_report

    verify_path = data_dir / "verify-report.json"
    if verify_path.is_file():
        try:
            raw = json.loads(verify_path.read_text(encoding="utf-8"))
            report = raw.get("login_entry_report")
            if isinstance(report, dict):
                return filter_login_entry_report(report, raw_config)
        except (json.JSONDecodeError, OSError):
            pass
    return None


def load_sessions(
    raw_config: dict[str, Any] | None, data_dir: Path | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return all_account_auths_with_meta(raw_config, data_dir=data_dir)


def discover_logout_urls(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
) -> list[str]:
    cfg = (raw_config or {}).get("diagnosis_4_2") or {}
    configured = [str(u).strip() for u in cfg.get("logout_urls") or [] if str(u).strip()]
    seen = {probe_url(u).rstrip("/") for u in configured}
    out = list(configured)

    tree = load_api_tree(data_dir)
    if tree is None:
        return out

    for ep in filter_endpoints_by_probe_bases(tree.endpoints, raw_config):
        if ep.method.upper() not in ("POST", "DELETE"):
            continue
        path = ep.path.split("?")[0]
        if not LOGOUT_PATH_RE.search(path):
            continue
        full = probe_url(build_full_url(ep.base_url, ep.path)).rstrip("/")
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out


def inventory_auth_logout_gap(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
    logout_urls: list[str] | None = None,
) -> dict[str, Any] | None:
    """True when inventory has login API(s) but no logout endpoint."""
    if logout_urls:
        return None
    tree = load_api_tree(data_dir)
    if tree is None:
        return None

    login_endpoints: list[str] = []
    logout_endpoints: list[str] = []
    for ep in filter_endpoints_by_probe_bases(tree.endpoints, raw_config):
        path = ep.path.split("?")[0]
        method = ep.method.upper()
        if method in ("POST", "PUT") and LOGIN_PATH_RE.search(path):
            login_endpoints.append(f"{method} {ep.base_url}{path}")
        if method in ("POST", "DELETE") and LOGOUT_PATH_RE.search(path):
            logout_endpoints.append(f"{method} {ep.base_url}{path}")

    if not login_endpoints or logout_endpoints:
        return None
    return {
        "login_endpoints": login_endpoints[:8],
        "logout_endpoints": logout_endpoints,
    }


def no_server_logout_finding(
    gap: dict[str, Any],
    *,
    email: str | None,
    login_url: str | None,
) -> DiagnosisFinding:
    samples = gap.get("login_endpoints") or []
    sample = samples[0] if samples else "login API"
    return DiagnosisFinding(
        severity="medium",
        message=(
            f"[4-2] No server logout API in inventory (client-only logout likely) — "
            f"e.g. `{sample}`"
        ),
        evidence={
            "rule_id": "4-2-no-server-logout-api",
            "reason": "login endpoints present but no logout/sign-out API in inventory or config",
            "email": email,
            "login_url": login_url,
            "login_endpoints": samples,
            "remediation": (
                "Add POST /api/v1/auth/logout that revokes refresh tokens server-side, "
                "or document stateless JWT expiry-only logout policy"
            ),
        },
    )


def pick_probe_account(
    sessions: list[dict[str, Any]],
    accounts: list[dict[str, str]],
    login_report: dict[str, Any] | None,
    *,
    raw_config: dict[str, Any] | None = None,
    override_email: str | None,
) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    if override_email:
        for account in valid_login_accounts(accounts):
            if account.get("email") == override_email:
                for session in sessions:
                    if session.get("email") == override_email:
                        return account, session
        return None, None

    for session in sessions:
        email = str(session.get("email") or "")
        for account in valid_login_accounts(accounts):
            if account.get("email") != email:
                continue
            return account, session

    if login_report:
        auth_cfg = (raw_config or {}).get("auth") or {}
        entries = configured_login_entries(auth_cfg)
        for account in valid_login_accounts(accounts):
            urls = login_urls_for_account(account, entries, login_report)
            if urls:
                return account, None
    return None, None


def resolve_login_url_for_account(
    account: dict[str, str],
    session: dict[str, Any] | None,
    raw_config: dict[str, Any] | None,
    login_report: dict[str, Any] | None,
) -> str | None:
    if session and session.get("login_url"):
        return str(session["login_url"])
    auth_cfg = (raw_config or {}).get("auth") or {}
    entries = configured_login_entries(auth_cfg)
    urls = login_urls_for_account(account, entries, login_report)
    return urls[0] if urls else None


def resolve_probe_base(
    session: dict[str, Any] | None,
    login_url: str | None,
    raw_config: dict[str, Any] | None,
) -> str:
    if session:
        for key in ("base_url",):
            base = str(session.get(key) or "").rstrip("/")
            if base:
                return base
    if login_url:
        from urllib.parse import urlparse

        parsed = urlparse(login_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    bases = collect_probe_base_urls(raw_config)
    return bases[0].rstrip("/") if bases else ""


def pick_test_accounts() -> list[dict[str, str]]:
    return load_test_accounts().get("accounts") or []
