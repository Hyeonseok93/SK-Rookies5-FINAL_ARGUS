"""Login-entry Set-Cookie static analysis (HttpOnly / Secure / SameSite) for 4-1."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.services.auth_probe_service import (
    DIAGNOSIS_LOGIN_TIMEOUT,
    load_cached_account_auths,
    login_account_at,
    valid_login_accounts,
)
from app.services.zap_util import probe_url
from diagnosis.cookie_flags import scan_cookie_attributes
from diagnosis.result import DiagnosisFinding


def _account_for_login_url(login_report: dict[str, Any] | None, login_url: str) -> str | None:
    if not login_report:
        return None
    normalized = probe_url(login_url).rstrip("/")
    for row in login_report.get("accounts") or []:
        if not isinstance(row, dict):
            continue
        for ok_url in row.get("successful_login_urls") or []:
            if probe_url(str(ok_url)).rstrip("/") == normalized:
                return str(row.get("email") or "") or None
    return None


def _pick_account(
    email: str | None,
    accounts: list[dict[str, str]],
) -> dict[str, str] | None:
    if not email:
        return None
    for account in valid_login_accounts(accounts):
        if account.get("email") == email:
            return account
    return None


def _cookie_lines_from_cache(
    cached: list[dict[str, Any]],
    *,
    login_url: str,
    email: str,
) -> list[str] | None:
    target_url = probe_url(login_url).rstrip("/")
    for session in cached:
        if session.get("email") != email:
            continue
        if probe_url(str(session.get("login_url") or "")).rstrip("/") != target_url:
            continue
        lines = session.get("set_cookie_lines")
        if isinstance(lines, list) and lines:
            return [str(x) for x in lines if x]
    return None


def collect_login_cookie_samples(
    auth_cfg: dict[str, Any],
    accounts: list[dict[str, str]],
    login_report: dict[str, Any] | None,
    *,
    data_dir: Any = None,
    timeout: float | None = None,
    refresh: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return Set-Cookie lines per login entry (cache first, then live login)."""
    stats: dict[str, Any] = {
        "entries": 0,
        "from_cache": 0,
        "live_login": 0,
        "errors": 0,
        "empty_cookies": 0,
    }
    samples: list[dict[str, Any]] = []

    entries = (login_report or {}).get("login_entries") or []
    if not entries:
        return samples, stats

    cached = [] if refresh else load_cached_account_auths(data_dir)
    client_timeout = timeout if timeout is not None else DIAGNOSIS_LOGIN_TIMEOUT

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        login_url = str(entry.get("url") or "")
        if not login_url:
            continue
        stats["entries"] += 1

        email = _account_for_login_url(login_report, login_url)
        account = _pick_account(email, accounts)
        if account is None and valid_login_accounts(accounts):
            account = valid_login_accounts(accounts)[0]
            email = account.get("email")

        cookie_lines: list[str] | None = None
        source = "none"

        if account and email and not refresh:
            cookie_lines = _cookie_lines_from_cache(cached, login_url=login_url, email=str(email))
            if cookie_lines:
                source = "verify_cache"
                stats["from_cache"] += 1

        if cookie_lines is None and account:
            try:
                session = login_account_at(
                    auth_cfg,
                    account,
                    login_url,
                    timeout=client_timeout,
                )
                cookie_lines = list(session.get("set_cookie_lines") or [])
                source = "live_login"
                stats["live_login"] += 1
            except Exception as exc:
                stats["errors"] += 1
                samples.append(
                    {
                        "login_url": login_url,
                        "login_label": entry.get("label"),
                        "email": email,
                        "source": "error",
                        "error": str(exc)[:200],
                        "set_cookie_lines": [],
                    }
                )
                continue

        if not cookie_lines:
            stats["empty_cookies"] += 1

        probed_url = probe_url(login_url)
        samples.append(
            {
                "login_url": probed_url,
                "login_label": entry.get("label"),
                "email": email,
                "source": source,
                "is_https": urlparse(probed_url).scheme.lower() == "https",
                "set_cookie_lines": cookie_lines or [],
            }
        )

    return samples, stats


def run_cookie_attribute_probes(
    auth_cfg: dict[str, Any],
    accounts: list[dict[str, str]],
    login_report: dict[str, Any] | None,
    *,
    data_dir: Any = None,
    strict: bool = True,
    timeout: float = 8.0,
    refresh: bool = False,
    make_finding_fn: Any = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    auth_cookie_name = str(auth_cfg.get("cookie_name") or "accessToken")
    auth_names = {auth_cookie_name}

    samples, stats = collect_login_cookie_samples(
        auth_cfg,
        accounts,
        login_report,
        data_dir=data_dir,
        timeout=timeout,
        refresh=refresh,
    )

    findings: list[DiagnosisFinding] = []
    stats["issues"] = 0
    stats["by_check_type"] = {}

    for sample in samples:
        if sample.get("error"):
            continue
        lines = sample.get("set_cookie_lines") or []
        if not lines:
            continue

        issues = scan_cookie_attributes(
            lines,
            is_https=bool(sample.get("is_https")),
            strict=strict,
            auth_cookie_names=auth_names,
        )
        for issue in issues:
            stats["issues"] += 1
            stats["by_check_type"][issue.check_type] = stats["by_check_type"].get(issue.check_type, 0) + 1
            if make_finding_fn:
                findings.append(
                    make_finding_fn(
                        issue=issue,
                        sample=sample,
                    )
                )

    return findings, stats
