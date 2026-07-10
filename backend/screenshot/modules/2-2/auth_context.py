"""Resolve auth sessions for 2-2 evidence replay (same path as diagnosis scanner)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from diagnosis.auth_session_pool import DiagnosisAuthPool

UNAUTH_DOWNLOAD_RULE = "2-2-unauth-download"
ANONYMOUS_ONLY_TRIGGERS = frozenset(
    {
        "unauth_download_no_account",
        "unauth_download_anonymous",
    }
)


def create_auth_pool(raw_config: dict[str, Any], *, data_dir: Path) -> DiagnosisAuthPool:
    return DiagnosisAuthPool(raw_config, data_dir=data_dir, refresh_on_start=True)


def is_unauth_download(evidence: dict[str, Any] | None = None, *, rule_id: str = "") -> bool:
    rid = rule_id or str((evidence or {}).get("rule_id") or "")
    return rid == UNAUTH_DOWNLOAD_RULE


def session_for_email(auth_pool: DiagnosisAuthPool, email: str) -> dict[str, Any] | None:
    wanted = str(email or "").strip()
    if not wanted:
        return None
    for session in auth_pool.sessions():
        if str(session.get("email") or "").strip() == wanted:
            return session
    return None


def authenticated_auth_for_evidence(
    evidence: dict[str, Any],
    *,
    auth_pool: DiagnosisAuthPool,
) -> dict[str, Any] | None:
    """Session used for the authenticated/normal side of a finding."""
    trigger = str(evidence.get("trigger") or "")
    if trigger in ANONYMOUS_ONLY_TRIGGERS:
        return None
    email = str(evidence.get("account_email") or "").strip()
    matched = session_for_email(auth_pool, email)
    if matched is not None:
        return matched
    return auth_pool.primary()


def account_auth_for_evidence(
    evidence: dict[str, Any],
    *,
    auth_pool: DiagnosisAuthPool,
) -> dict[str, Any] | None:
    """
    Auth attached to the primary probe for non-unauth rules.

    Unauth-download findings intentionally return None here so callers that only
    need a single auth mode stay anonymous; use ``authenticated_auth_for_evidence``
    when building the authenticated baseline for the 4-shot UI capture.
    """
    if is_unauth_download(evidence):
        return None

    email = str(evidence.get("account_email") or "").strip()
    matched = session_for_email(auth_pool, email)
    if matched is not None:
        return matched
    return auth_pool.primary()
