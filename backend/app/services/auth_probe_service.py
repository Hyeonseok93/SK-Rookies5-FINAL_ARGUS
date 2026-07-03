"""Login saved test accounts and build auth contexts for probes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services.zap_util import probe_url

AUTH_HEADER_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "x-auth-token",
        "x-access-token",
        "x-api-key",
    }
)

VERIFY_LOGIN_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
DIAGNOSIS_LOGIN_TIMEOUT = httpx.Timeout(5.0, connect=2.0)
VERIFY_REPORT_NAME = "verify-report.json"


def valid_login_accounts(accounts: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        a
        for a in accounts
        if a.get("email") and "@" in str(a["email"]) and str(a.get("password", "")).strip()
    ]


def login_label_from_url(url: str) -> str:
    path = urlparse(url).path.rstrip("/") or "/"
    tail = path.split("/")[-1]
    return tail or path


def configured_login_entries(auth_cfg: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """Login endpoints: inventory auto-discovery + dashboard-prepared URLs."""
    from app.services.login_discovery_service import _load_raw_config, resolve_login_entries

    raw_config = _load_raw_config()
    cfg = auth_cfg if auth_cfg is not None else (raw_config.get("auth") or {})
    return resolve_login_entries(cfg, raw_config)


def login_account_at(
    auth_cfg: dict[str, Any],
    account: dict[str, str],
    login_url: str,
    *,
    timeout: httpx.Timeout | float | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    login_url = probe_url(login_url)
    id_field = auth_cfg.get("id_field", "email")
    pw_field = auth_cfg.get("pw_field", "password")
    token_field = auth_cfg.get("token_field", "cookie.accessToken")
    delivery = auth_cfg.get("delivery", "cookie")
    cookie_name = auth_cfg.get("cookie_name", "accessToken")
    client_timeout = timeout if timeout is not None else VERIFY_LOGIN_TIMEOUT

    req_headers = {k: str(v) for k, v in (extra_headers or {}).items() if k and v is not None}

    with httpx.Client(timeout=client_timeout) as client:
        resp = client.post(
            login_url,
            json={id_field: account["email"], pw_field: account["password"]},
            headers=req_headers or None,
        )
        resp.raise_for_status()

        from inventory.auth_surfaces import enrich_auth_session

        if str(token_field).startswith("cookie."):
            cname = token_field.split(".", 1)[1]
            token = resp.cookies.get(cname)
            if not token:
                raise ValueError(f"Cookie '{cname}' not found after login")
            session = {
                "account_id": account.get("id", ""),
                "email": account["email"],
                "token": str(token),
                "delivery": "cookie",
                "cookie_name": cname,
                "login_url": login_url,
                "login_label": login_label_from_url(login_url),
                "set_cookie_lines": resp.headers.get_list("set-cookie"),
            }
            return enrich_auth_session(session, resp, auth_cfg=auth_cfg)

        data = resp.json()
        keys = str(token_field).split(".")
        node: Any = data
        for key in keys:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        if not node:
            raise ValueError(f"Token field '{token_field}' not found")
        session = {
            "account_id": account.get("id", ""),
            "email": account["email"],
            "token": str(node),
            "delivery": delivery,
            "cookie_name": cookie_name,
            "login_url": login_url,
            "login_label": login_label_from_url(login_url),
            "set_cookie_lines": resp.headers.get_list("set-cookie"),
        }
        return enrich_auth_session(session, resp, auth_cfg=auth_cfg)


def login_urls_for_account(
    account: dict[str, str],
    entries: list[dict[str, str]],
    login_report: dict[str, Any] | None,
) -> list[str]:
    """성공 이력이 있으면 해당 URL을 우선하고, 실패 이력만 있으면 모두 다시 시도합니다."""
    entry_urls = [str(e.get("url") or "") for e in entries if e.get("url")]
    if not login_report:
        return entry_urls

    email = str(account.get("email") or "")
    row = next(
        (r for r in login_report.get("accounts") or [] if isinstance(r, dict) and r.get("email") == email),
        None,
    )
    if not row:
        return entry_urls

    ok_urls = [str(u) for u in row.get("successful_login_urls") or [] if u]
    if ok_urls:
        return ok_urls

    # 이전 실패는 일시적인 네트워크 장애나 대상 서버의 준비 지연 때문일 수 있습니다.
    # 성공 이력이 하나도 없다면 현재 진단에서는 모든 로그인 URL을 다시 확인합니다.
    return entry_urls


def dedupe_account_auths(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for session in sessions:
        email = str(session.get("email") or "").lower()
        login_url = str(session.get("login_url") or "").rstrip("/")
        key = (email, login_url)
        if key in seen:
            continue
        seen.add(key)
        out.append(session)
    return out


def load_verify_report(data_dir: Path | None) -> dict[str, Any] | None:
    if data_dir is None:
        return None
    path = data_dir / VERIFY_REPORT_NAME
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def load_cached_account_auths(data_dir: Path | None) -> list[dict[str, Any]]:
    report = load_verify_report(data_dir)
    if not report:
        return []
    cached = report.get("account_auths")
    if not isinstance(cached, list):
        return []
    return dedupe_account_auths([s for s in cached if isinstance(s, dict) and s.get("token")])


def login_all_accounts(
    auth_cfg: dict[str, Any],
    accounts: list[dict[str, str]],
    *,
    timeout: httpx.Timeout | float | None = None,
    login_report: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Try each account against configured login entry URLs (optionally filtered by verify report)."""
    entries = configured_login_entries(auth_cfg)
    if not entries:
        return []

    logged_in: list[dict[str, Any]] = []
    client_timeout = timeout if timeout is not None else VERIFY_LOGIN_TIMEOUT
    for account in valid_login_accounts(accounts):
        for login_url in login_urls_for_account(account, entries, login_report):
            try:
                logged_in.append(
                    login_account_at(auth_cfg, account, login_url, timeout=client_timeout)
                )
            except Exception:
                continue
    return logged_in


def resolve_account_auths(
    auth_cfg: dict[str, Any],
    accounts: list[dict[str, str]],
    *,
    data_dir: Path | None = None,
    refresh: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Verify cache first; fall back to fast targeted live login."""
    meta: dict[str, Any] = {"source": "none", "sessions": 0}
    if not accounts:
        return [], meta

    login_report = None
    report = load_verify_report(data_dir)
    if report:
        login_report = report.get("login_entry_report")
        if not isinstance(login_report, dict):
            login_report = None

    if data_dir and not refresh:
        cached = load_cached_account_auths(data_dir)
        if cached:
            meta = {
                "source": "verify_cache",
                "sessions": len(cached),
                "checked_at": report.get("checked_at") if report else None,
            }
            return cached, meta

    sessions = login_all_accounts(
        auth_cfg,
        accounts,
        timeout=DIAGNOSIS_LOGIN_TIMEOUT,
        login_report=login_report,
    )
    sessions = dedupe_account_auths(sessions)
    meta = {
        "source": "live_login",
        "sessions": len(sessions),
        "login_report_guided": login_report is not None,
    }
    return sessions, meta


def build_login_entry_report(
    auth_cfg: dict[str, Any],
    accounts: list[dict[str, str]],
    sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize which accounts succeed on which login entry points."""
    entries = configured_login_entries(auth_cfg)
    entry_urls = [e["url"] for e in entries]
    ok_by_email: dict[str, list[str]] = {}
    for session in sessions:
        email = str(session.get("email") or "")
        url = str(session.get("login_url") or "")
        if email and url:
            ok_by_email.setdefault(email, [])
            if url not in ok_by_email[email]:
                ok_by_email[email].append(url)

    account_rows: list[dict[str, Any]] = []
    entry_specific_accounts: list[str] = []

    for account in valid_login_accounts(accounts):
        email = account["email"]
        ok_urls = ok_by_email.get(email, [])
        failed_urls = [u for u in entry_urls if u not in ok_urls]
        exclusive = ok_urls[0] if len(entry_urls) > 1 and len(ok_urls) == 1 else None
        entry_specific = exclusive is not None
        if entry_specific:
            entry_specific_accounts.append(email)
        account_rows.append(
            {
                "email": email,
                "successful_login_urls": ok_urls,
                "failed_login_urls": failed_urls,
                "exclusive_login_url": exclusive,
                "entry_specific": entry_specific,
            }
        )

    return {
        "login_entries": entries,
        "accounts": account_rows,
        "entry_specific_accounts": entry_specific_accounts,
        "session_count": len(sessions),
    }


def auth_session_label(ctx: dict[str, Any]) -> str:
    email = str(ctx.get("email") or ctx.get("account_id") or "account")
    label = str(ctx.get("login_label") or login_label_from_url(str(ctx.get("login_url") or "")))
    return f"{email} · {label}"


def auth_passes(
    account_auths: list[dict[str, Any]],
    *,
    include_anonymous: bool = True,
) -> list[tuple[dict[str, Any] | None, str]]:
    passes: list[tuple[dict[str, Any] | None, str]] = []
    if include_anonymous:
        passes.append((None, "anonymous"))
    for ctx in account_auths:
        passes.append((ctx, auth_session_label(ctx)))
    return passes


def probe_passes_for_endpoint(
    ep: Any,
    account_auths: list[dict[str, Any]],
    *,
    include_anonymous: bool = True,
) -> list[tuple[dict[str, Any] | None, str]]:
    """All auth sessions for every endpoint — no path-based filtering."""
    return auth_passes(account_auths, include_anonymous=include_anonymous)


def account_access_allowed(http_status: int | None) -> bool:
    if http_status is None:
        return False
    return 200 <= int(http_status) < 400


def account_access_for_endpoint(
    results: list[dict[str, Any]],
    endpoint_id: str,
) -> list[dict[str, Any]]:
    rows = [r for r in results if str(r.get("endpoint_id", "")) == endpoint_id]
    out: list[dict[str, Any]] = []
    for row in rows:
        code = row.get("http_status")
        out.append(
            {
                "auth_mode": str(row.get("auth_mode") or "anonymous"),
                "account_email": row.get("account_email"),
                "login_url": row.get("login_url"),
                "login_label": row.get("login_label"),
                "http_status": code,
                "status": str(row.get("status") or ""),
                "note": str(row.get("note") or ""),
                "allowed": account_access_allowed(code),
            }
        )
    return sorted(out, key=lambda r: (0 if r["auth_mode"] == "anonymous" else 1, str(r["auth_mode"])))


def infer_endpoint_auth_labels(results: list[dict[str, Any]]) -> list[str]:
    by_mode: dict[str, list[dict[str, Any]]] = {}
    for row in results:
        by_mode.setdefault(str(row.get("auth_mode", "")), []).append(row)

    def status_for(rows: list[dict[str, Any]]) -> int | None:
        for row in rows:
            code = row.get("http_status")
            if code is not None:
                return int(code)
        return None

    anon_status = status_for(by_mode.get("anonymous", []))
    authed_rows = [r for mode, rows in by_mode.items() if mode != "anonymous" for r in rows]
    authed_ok = any(account_access_allowed(r.get("http_status")) for r in authed_rows)

    labels: list[str] = []
    if anon_status is not None and anon_status < 400:
        labels.append("public")
    elif anon_status in (401, 403) and authed_ok:
        labels.append("authenticated")
    elif authed_ok and anon_status not in (404, 405, None):
        labels.append("authenticated")
    elif authed_ok and anon_status is None:
        labels.append("authenticated")

    if not labels and any(r.get("include_in_final") for r in results):
        labels.append("unknown")
    return sorted(set(labels))


def auth_mode_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in results:
        mode = str(row.get("auth_mode") or "anonymous")
        counts[mode] = counts.get(mode, 0) + 1
    return counts
