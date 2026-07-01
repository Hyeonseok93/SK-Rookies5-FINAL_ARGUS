"""Guideline 4-1 — cookie cross-use and tamper heuristics (phase A)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from diagnosis.result import DiagnosisFinding

MIN_CROSS_LEAK_BODY_BYTES = 48

ADMIN_API_PREFIXES = ("/api/v1/admin", "/admin-api/", "/v1/admin/")

SENSITIVE_PATH_HINTS = re.compile(
    r"(?i)(admin|booking|payment|profile|account|user|order|export|download|manage)",
)


def is_admin_api_path(path: str) -> bool:
    lower = (path or "").lower()
    return any(p in lower for p in ADMIN_API_PREFIXES) or "/admin/" in lower


def is_probe_candidate(path: str, *, ep: Any = None) -> bool:
    if is_admin_api_path(path):
        return True
    if SENSITIVE_PATH_HINTS.search(path or ""):
        return True
    if ep is not None:
        for hdr in getattr(ep, "request_headers", []) or []:
            if (hdr.name or "").lower() == "cookie" and hdr.role in ("auth", "input"):
                return True
    return False


def access_allowed(status: int | None) -> bool:
    if status is None:
        return False
    return 200 <= int(status) < 400


def body_fingerprint(body: bytes | str | None) -> dict[str, Any]:
    raw = body if isinstance(body, bytes) else (body or "").encode("utf-8", errors="replace")
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def cross_cookie_leak_detected(
    owner_body: bytes | str | None,
    other_body: bytes | str | None,
    owner_session: dict[str, Any] | None = None,
    other_session: dict[str, Any] | None = None,
    *,
    path: str = "",
) -> bool:
    """True when other session received owner-identified data (not generic /api/v1-style payload)."""
    if owner_session is None or other_session is None:
        owner_fp = body_fingerprint(owner_body)
        other_fp = body_fingerprint(other_body)
        if owner_fp["size"] < MIN_CROSS_LEAK_BODY_BYTES or other_fp["size"] < MIN_CROSS_LEAK_BODY_BYTES:
            return False
        return owner_fp["sha256"] == other_fp["sha256"]

    from inventory.auth_identity import cross_account_leak_assessment

    leaked, _meta = cross_account_leak_assessment(
        owner_body,
        other_body,
        owner_session,
        other_session,
        path=path,
        min_body_bytes=MIN_CROSS_LEAK_BODY_BYTES,
    )
    return leaked


def cross_cookie_leak_meta(
    owner_body: bytes | str | None,
    other_body: bytes | str | None,
    owner_session: dict[str, Any],
    other_session: dict[str, Any],
    *,
    path: str = "",
) -> dict[str, Any]:
    from inventory.auth_identity import cross_account_leak_assessment

    leaked, meta = cross_account_leak_assessment(
        owner_body,
        other_body,
        owner_session,
        other_session,
        path=path,
        min_body_bytes=MIN_CROSS_LEAK_BODY_BYTES,
    )
    meta["leak_detected"] = leaked
    return meta


def session_key(session: dict[str, Any]) -> tuple[str, str]:
    return (
        str(session.get("email") or "").lower(),
        str(session.get("login_url") or "").rstrip("/"),
    )


def cross_session_pairs(sessions: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """All ordered (owner, other) pairs — different email or different login entry."""
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for owner in sessions:
        for other in sessions:
            if session_key(owner) == session_key(other):
                continue
            pairs.append((owner, other))
    return pairs


def tampered_auth_variants(
    session: dict[str, Any],
    profile: str = "cookie_access",
    *,
    other_sessions: list[dict[str, Any]] | None = None,
    include_partial_cross: bool = True,
) -> list[tuple[str, dict[str, Any] | None]]:
    from inventory.auth_surfaces import tamper_surface_variants

    return tamper_surface_variants(
        session,
        profile,
        other_sessions=other_sessions,
        include_partial_cross=include_partial_cross,
    )


def session_with_profile(session: dict[str, Any], profile: str) -> dict[str, Any]:
    return {**session, "_auth_profile": profile}


def build_isolated_confirm_ctx(tampered: dict[str, Any] | None, label: str) -> dict[str, Any] | None:
    from inventory.auth_surfaces import build_isolated_confirm_ctx as _build

    return _build(tampered, label)


def tamper_label_targets_api_auth(label: str) -> bool:
    from inventory.auth_surfaces import tamper_label_targets_api_auth as _allowed

    return _allowed(label)


def make_cross_cookie_finding(
    *,
    rule_id: str,
    severity: str,
    owner: dict[str, Any],
    other: dict[str, Any],
    ep: Any,
    url: str,
    owner_status: int | None,
    other_status: int | None,
    owner_body_fp: dict[str, Any],
    other_body_fp: dict[str, Any],
    trigger: str,
    auth_profile: str = "cookie_access",
    leak_meta: dict[str, Any] | None = None,
) -> DiagnosisFinding:
    owner_label = f"{owner.get('email')} · {owner.get('login_label')}"
    other_label = f"{other.get('email')} · {other.get('login_label')}"
    return DiagnosisFinding(
        severity=severity,
        message=(
            f"Cross-account auth leak [{auth_profile}]: {other_label} received the same response body as "
            f"{owner_label} on {ep.method} {ep.path} (HTTP {other_status})"
        ),
        evidence={
            "rule_id": rule_id,
            "trigger": trigger,
            "auth_profile": auth_profile,
            "engine": "httpx",
            "endpoint_id": ep.endpoint_id,
            "method": ep.method,
            "path": ep.path,
            "base_url": ep.base_url,
            "url": url,
            "owner_email": owner.get("email"),
            "owner_login_url": owner.get("login_url"),
            "owner_login_label": owner.get("login_label"),
            "other_email": other.get("email"),
            "other_login_url": other.get("login_url"),
            "other_login_label": other.get("login_label"),
            "owner_http_status": owner_status,
            "other_http_status": other_status,
            "owner_body_sha256": owner_body_fp.get("sha256"),
            "owner_body_size": owner_body_fp.get("size"),
            "other_body_sha256": other_body_fp.get("sha256"),
            "other_body_size": other_body_fp.get("size"),
            "bodies_identical": True,
            "related_sections": ["4-1", "4-3"],
            **(leak_meta or {}),
        },
    )


def make_tamper_finding(
    *,
    session: dict[str, Any],
    ep: Any,
    url: str,
    tamper_label: str,
    owner_status: int | None,
    tamper_status: int | None,
    auth_profile: str = "cookie_access",
    confirm_status: int | None = None,
    isolated_profile: str | None = None,
) -> DiagnosisFinding:
    confirmed = isolated_profile is not None and confirm_status is not None
    msg = (
        f"Tampered auth accepted [{auth_profile}] ({tamper_label}): {ep.method} {ep.path} "
        f"(HTTP {tamper_status}, owner HTTP {owner_status})"
    )
    if confirmed:
        msg += f" — confirmed on isolated [{isolated_profile}] HTTP {confirm_status}"
    return DiagnosisFinding(
        severity="high",
        message=msg,
        evidence={
            "rule_id": "4-1-cookie-tamper",
            "trigger": tamper_label,
            "auth_profile": auth_profile,
            "tamper_confirmed_isolated": confirmed,
            "isolated_profile": isolated_profile,
            "confirm_http_status": confirm_status,
            "engine": "httpx",
            "endpoint_id": ep.endpoint_id,
            "method": ep.method,
            "path": ep.path,
            "base_url": ep.base_url,
            "url": url,
            "account_email": session.get("email"),
            "login_url": session.get("login_url"),
            "login_label": session.get("login_label"),
            "owner_http_status": owner_status,
            "tamper_http_status": tamper_status,
            "related_sections": ["4-1"],
        },
    )


def make_cookie_attr_finding(*, issue: Any, sample: dict[str, Any]) -> DiagnosisFinding:
    label = sample.get("login_label") or sample.get("login_url") or "login"
    email = sample.get("email") or "account"
    ev = issue.to_dict()
    return DiagnosisFinding(
        severity=issue.severity,
        message=(
            f"Cookie flag issue ({issue.reason}): `{issue.cookie_name}` "
            f"on {email} · {label}"
        ),
        evidence={
            **ev,
            "trigger": issue.check_type,
            "engine": "inventory",
            "source": sample.get("source"),
            "login_url": sample.get("login_url"),
            "login_label": sample.get("login_label"),
            "account_email": sample.get("email"),
            "is_https": sample.get("is_https"),
            "related_sections": ["4-1", "7-4"],
        },
    )


def auth_requirement_info(auth_index: dict[str, Any]) -> DiagnosisFinding | None:
    if not auth_index:
        return None
    from diagnosis.endpoint_auth import auth_requirement_summary

    summary = auth_requirement_summary(auth_index)
    total = sum(summary.values())
    if total == 0:
        return None
    return DiagnosisFinding(
        severity="info",
        message=(
            f"Endpoint auth requirement index ({total} from verify): "
            f"auth_required {summary.get('auth_required', 0)}, "
            f"public {summary.get('public', 0)}, "
            f"optional {summary.get('optional_auth', 0)}"
        ),
        evidence={
            "rule_id": "4-1-auth-requirement-index",
            "trigger": "verify_report",
            "engine": "inventory",
            "summary": summary,
            "cookie_probe_relevant": summary.get("auth_required", 0),
            "related_sections": ["4-1"],
        },
    )


def login_relationship_info(login_report: dict[str, Any] | None) -> DiagnosisFinding | None:
    if not login_report:
        return None
    accounts = login_report.get("accounts") or []
    if not accounts:
        return None
    rows = []
    for row in accounts:
        if not isinstance(row, dict):
            continue
        rows.append(
            {
                "email": row.get("email"),
                "successful_login_urls": row.get("successful_login_urls"),
                "entry_specific": row.get("entry_specific"),
                "exclusive_login_url": row.get("exclusive_login_url"),
            }
        )
    if not rows:
        return None
    return DiagnosisFinding(
        severity="info",
        message=f"Login entry × account matrix ({len(rows)} account(s)) from verify report",
        evidence={
            "rule_id": "4-1-login-matrix",
            "trigger": "login_entry_report",
            "engine": "inventory",
            "accounts": rows,
            "login_entries": login_report.get("login_entries"),
            "entry_specific_accounts": login_report.get("entry_specific_accounts"),
            "related_sections": ["4-1"],
        },
    )
