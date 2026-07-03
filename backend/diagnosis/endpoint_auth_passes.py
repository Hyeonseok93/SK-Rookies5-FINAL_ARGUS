"""Origin- and path-aware auth session selection for diagnosis probes."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from diagnosis.replay.normalize import canonical_login_url, probe_base_key
from inventory.schema import Endpoint


def _separation_rules():
    """Load 3-4 separation rules without import cycles at module load."""
    import importlib.util
    import sys

    mod_name = "diag_endpoint_auth_separation_rules"
    cached = sys.modules.get(mod_name)
    if cached is not None:
        return cached

    path = Path(__file__).resolve().parent / "modules" / "3-4" / "separation_rules.py"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _classify_login_entry(entry: dict[str, Any]) -> str:
    rules = _separation_rules()
    return rules.classify_login_entry(entry)


def is_admin_api_path(path: str) -> bool:
    rules = _separation_rules()
    return rules.is_admin_api_path(path)


def load_login_report(
    data_dir: Path | None,
    raw_config: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    from app.services.auth_probe_service import load_verify_report
    from diagnosis.replay.normalize import filter_login_entry_report

    report = load_verify_report(data_dir)
    if not report:
        return None
    login_report = report.get("login_entry_report")
    if not isinstance(login_report, dict):
        return None
    return filter_login_entry_report(login_report, raw_config)


def session_origin_key(session: dict[str, Any]) -> str:
    login_url = str(session.get("login_url") or "").strip()
    if login_url:
        parsed = urlparse(login_url)
        if parsed.scheme and parsed.hostname:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return probe_base_key(f"{parsed.scheme}://{parsed.hostname}:{port}")
    base_url = str(session.get("base_url") or "").strip()
    if base_url:
        return probe_base_key(base_url)
    return ""


def endpoint_origin_key(ep: Endpoint) -> str:
    return probe_base_key(str(ep.base_url or ""))


def probe_origin_key(base_url: str) -> str:
    return probe_base_key(base_url)


def _session_login_class(session: dict[str, Any]) -> str:
    return _classify_login_entry(
        {
            "url": session.get("login_url"),
            "label": session.get("login_label"),
        }
    )


def _account_succeeded_at_url(
    email: str,
    login_url: str,
    login_report: dict[str, Any] | None,
) -> bool:
    if not login_report or not email or not login_url:
        return False
    target = canonical_login_url(login_url)
    for row in login_report.get("accounts") or []:
        if not isinstance(row, dict) or row.get("email") != email:
            continue
        for raw in row.get("successful_login_urls") or []:
            if canonical_login_url(str(raw)) == target:
                return True
    return False


def filter_sessions_for_probe(
    *,
    base_url: str,
    path: str,
    sessions: list[dict[str, Any]],
    login_report: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Keep sessions whose login origin matches the probe origin and path class."""
    if not sessions:
        return []

    origin = probe_origin_key(base_url)
    origin_matched: list[dict[str, Any]] = []
    seen_emails: set[tuple[str, str]] = set()
    for session in sessions:
        if session_origin_key(session) != origin:
            continue
        email = str(session.get("email") or "").lower()
        login_url = str(session.get("login_url") or "")
        dedupe_key = (email, canonical_login_url(login_url))
        if dedupe_key in seen_emails:
            continue
        seen_emails.add(dedupe_key)
        origin_matched.append(session)

    if not origin_matched:
        return []

    if is_admin_api_path(path):
        admin_sessions = [s for s in origin_matched if _session_login_class(s) == "admin"]
        if admin_sessions:
            return admin_sessions
        entry_specific = [
            s
            for s in origin_matched
            if _account_succeeded_at_url(
                str(s.get("email") or ""),
                str(s.get("login_url") or ""),
                login_report,
            )
            and _classify_login_entry({"url": s.get("login_url")}) == "admin"
        ]
        if entry_specific:
            return entry_specific

    return origin_matched


def filter_sessions_for_endpoint(
    ep: Endpoint,
    sessions: list[dict[str, Any]],
    login_report: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return filter_sessions_for_probe(
        base_url=str(ep.base_url or ""),
        path=str(ep.path or ""),
        sessions=sessions,
        login_report=login_report,
    )


def filter_sessions_for_probe_target(
    target: dict[str, str],
    sessions: list[dict[str, Any]],
    login_report: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return filter_sessions_for_probe(
        base_url=str(target.get("base_url") or ""),
        path=str(target.get("path") or "/"),
        sessions=sessions,
        login_report=login_report,
    )


def primary_session_for_endpoint(
    ep: Endpoint,
    sessions: list[dict[str, Any]],
    login_report: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    matched = filter_sessions_for_endpoint(ep, sessions, login_report)
    return matched[0] if matched else None


def primary_session_for_probe(
    base_url: str,
    path: str,
    sessions: list[dict[str, Any]],
    login_report: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    matched = filter_sessions_for_probe(
        base_url=base_url,
        path=path,
        sessions=sessions,
        login_report=login_report,
    )
    return matched[0] if matched else None


def pick_account_for_login_entry(
    entry: dict[str, Any],
    accounts: list[dict[str, str]],
    login_report: dict[str, Any] | None = None,
    *,
    override_email: str | None = None,
) -> dict[str, str] | None:
    from app.services.auth_probe_service import valid_login_accounts

    valid = valid_login_accounts(accounts)
    if not valid:
        return None

    if override_email:
        for account in valid:
            if account.get("email") == override_email:
                return account
        return None

    entry_url = str(entry.get("url") or "")
    if login_report and entry_url:
        canon_entry = canonical_login_url(entry_url)
        for row in login_report.get("accounts") or []:
            if not isinstance(row, dict):
                continue
            email = str(row.get("email") or "")
            ok_urls = row.get("successful_login_urls") or []
            if email and any(canonical_login_url(str(u)) == canon_entry for u in ok_urls):
                for account in valid:
                    if account.get("email") == email:
                        return account

    if _classify_login_entry(entry) == "admin":
        for account in valid:
            if "admin" in str(account.get("email") or "").lower():
                return account

    return valid[0]


def build_probe_passes(
    ep: Endpoint,
    sessions: list[dict[str, Any]],
    *,
    login_report: dict[str, Any] | None = None,
    include_anonymous: bool = True,
    enable_auth_modes: bool = True,
) -> list[tuple[str, dict[str, str], dict[str, Any] | None]]:
    from diagnosis.probe_auth import probe_request_headers, session_auth_mode

    passes: list[tuple[str, dict[str, str], dict[str, Any] | None]] = []
    if include_anonymous:
        passes.append(("anonymous", {}, None))
    if enable_auth_modes:
        for session in filter_sessions_for_endpoint(ep, sessions, login_report):
            passes.append(
                (session_auth_mode(session), probe_request_headers(session), session)
            )
    return passes


def build_probe_passes_headers_only(
    ep: Endpoint,
    sessions: list[dict[str, Any]],
    *,
    login_report: dict[str, Any] | None = None,
    include_anonymous: bool = True,
    enable_auth_modes: bool = True,
) -> list[tuple[str, dict[str, str]]]:
    from diagnosis.probe_auth import probe_request_headers, session_auth_mode

    passes: list[tuple[str, dict[str, str]]] = []
    if include_anonymous:
        passes.append(("anonymous", {}))
    if enable_auth_modes:
        for session in filter_sessions_for_endpoint(ep, sessions, login_report):
            passes.append((session_auth_mode(session), probe_request_headers(session)))
    return passes


def probe_passes_for_endpoint(
    ep: Endpoint,
    account_auths: list[dict[str, Any]],
    *,
    login_report: dict[str, Any] | None = None,
    include_anonymous: bool = True,
) -> list[tuple[dict[str, Any] | None, str]]:
    from app.services.auth_probe_service import auth_session_label

    passes: list[tuple[dict[str, Any] | None, str]] = []
    if include_anonymous:
        passes.append((None, "anonymous"))
    for session in filter_sessions_for_endpoint(ep, account_auths, login_report):
        passes.append((session, auth_session_label(session)))
    return passes
