"""Targets and helpers for guideline 4-2."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.services.auth_probe_service import (
    configured_login_entries,
    login_urls_for_account,
    valid_login_accounts,
)
from app.services.test_accounts_service import load_test_accounts
from app.services.zap_util import probe_url
from diagnosis.probe_auth import all_account_auths_with_meta
from diagnosis.replay.normalize import (
    collect_probe_base_urls,
    filter_endpoints_by_probe_bases,
    probe_base_key,
)
from diagnosis.result import DiagnosisFinding
from inventory.schema import ApiTree, build_full_url
from inventory.load import load_api_tree

LOGOUT_PATH_RE = re.compile(r"(?i)(/(auth/)?(logout|sign-?out)(/|$)|/logout$)")
LOGIN_PATH_RE = re.compile(r"(?i)(/(auth/)?(login|sign-?in)(/|$)|/login$)")
REFRESH_PATH_RE = re.compile(
    r"(?i)(/(auth/)?refresh(/|$)|/token/refresh|/oauth2?/refresh)"
)
REFRESH_PATH_NEGATIVE = re.compile(
    r"(?i)(login|logout|sign-?up|register|password|verify|check-email|check-nickname)"
)



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
    return all_account_auths_with_meta(raw_config, data_dir=data_dir, refresh=True)


def _refresh_base_score(ep: Endpoint, preferred_bases: set[str]) -> int:
    score = 0
    base = ep.base_url.rstrip("/")
    if probe_base_key(base) in preferred_bases:
        score += 10
    if ep.kind == "api":
        score += 5
    port = urlparse(base).port
    if port in (8080, 8081, 8000, 3000):
        score += 3
    if port == 5173:
        score -= 4
    return score


def discover_refresh_paths(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
) -> list[dict[str, str]]:
    """Refresh-token POST endpoints from api-tree (optional diagnosis_4_2.refresh_paths override)."""
    cfg = (raw_config or {}).get("diagnosis_4_2") or {}
    configured = [str(p).strip() for p in cfg.get("refresh_paths") or [] if str(p).strip()]
    if cfg.get("refresh_path"):
        configured.append(str(cfg["refresh_path"]).strip())

    seen_paths: set[str] = set()
    out: list[dict[str, str]] = []
    for raw_path in configured:
        path = raw_path if raw_path.startswith("/") else f"/{raw_path.lstrip('/')}"
        key = path.lower()
        if key in seen_paths:
            continue
        seen_paths.add(key)
        out.append({"path": path, "base_url": "", "url": path, "source": "config"})

    tree = load_api_tree(data_dir)
    if tree is None:
        return out

    preferred = {probe_base_key(b) for b in collect_probe_base_urls(raw_config)}
    best_by_path: dict[str, tuple[Endpoint, int]] = {}
    for ep in filter_endpoints_by_probe_bases(tree.endpoints, raw_config):
        if ep.method.upper() not in ("POST", "PUT", "PATCH"):
            continue
        path = ep.path.split("?")[0]
        if REFRESH_PATH_NEGATIVE.search(path):
            continue
        if not REFRESH_PATH_RE.search(path):
            continue
        key = path.lower()
        score = _refresh_base_score(ep, preferred)
        prev = best_by_path.get(key)
        if prev is None or score > prev[1]:
            best_by_path[key] = (ep, score)

    ranked = sorted(best_by_path.values(), key=lambda item: (-item[1], item[0].path))
    for ep, _score in ranked:
        path = ep.path.split("?")[0]
        key = path.lower()
        if key in seen_paths:
            continue
        seen_paths.add(key)
        full = probe_url(build_full_url(ep.base_url, path))
        out.append(
            {
                "path": path,
                "base_url": ep.base_url.rstrip("/"),
                "url": full,
                "source": "inventory",
            }
        )
    return out


def resolve_refresh_path_for_base(
    raw_config: dict[str, Any] | None,
    *,
    base_url: str,
    data_dir: Path | None = None,
) -> str | None:
    """Pick refresh path for probe base — inventory match first, else first discovered path."""
    entries = discover_refresh_paths(raw_config, data_dir=data_dir)
    if not entries:
        return None
    target_key = probe_base_key(probe_url(base_url.rstrip("/")))
    for entry in entries:
        entry_base = str(entry.get("base_url") or "").strip()
        if entry_base and probe_base_key(probe_url(entry_base)) == target_key:
            return str(entry["path"])
    for entry in entries:
        path = str(entry.get("path") or "").strip()
        if path:
            return path
    return None


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
    probe_path: str = "/api/v1/members/me",
) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    from diagnosis.endpoint_auth_passes import filter_sessions_for_probe, primary_session_for_probe

    probe_base = resolve_probe_base(sessions[0] if sessions else None, None, raw_config)
    matched = filter_sessions_for_probe(
        base_url=probe_base,
        path=probe_path,
        sessions=sessions,
        login_report=login_report,
    )
    if override_email:
        for account in valid_login_accounts(accounts):
            if account.get("email") == override_email:
                for session in sessions:
                    if session.get("email") == override_email:
                        return account, session
        return None, None

    session = primary_session_for_probe(probe_base, probe_path, sessions, login_report)
    if session:
        email = str(session.get("email") or "")
        for account in valid_login_accounts(accounts):
            if account.get("email") == email:
                return account, session

    for session in matched or sessions:
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
