"""Identity markers in API bodies — cross-account leak vs generic same response."""

from __future__ import annotations

import json
import re
from typing import Any

VERSION_ROOT_RE = re.compile(r"^/api/v\d+$", re.IGNORECASE)

# Paths that are never meaningful cross-account targets (version root, health, etc.)
CROSS_EXCLUDE_PATH_RE = re.compile(
    r"(?i)^/api/v\d+$|^/health$|^/actuator(?:/|$)|^/swagger|^/v3/api-docs",
)

IDENTITY_JSON_KEYS = frozenset(
    {
        "email",
        "username",
        "memberid",
        "member_id",
        "userid",
        "user_id",
        "sub",
        "nickname",
        "name",
    }
)


def is_cross_excluded_path(path: str) -> bool:
    normalized = (path or "").split("?", 1)[0].rstrip("/") or "/"
    return bool(CROSS_EXCLUDE_PATH_RE.match(normalized))


def session_identity_tokens(session: dict[str, Any]) -> set[str]:
    """Lowercase tokens expected to identify this account inside JSON/HTML bodies."""
    tokens: set[str] = set()
    email = str(session.get("email") or "").strip().lower()
    if email and "@" in email:
        tokens.add(email)
        local = email.split("@", 1)[0]
        if len(local) >= 2:
            tokens.add(local)
    username = str(session.get("username") or "").strip().lower()
    if username and "@" in username:
        tokens.add(username)
    member_id = session.get("member_id")
    if member_id is not None and str(member_id).strip():
        tokens.add(str(member_id).strip())
    return {t for t in tokens if len(t) >= 2 or t.isdigit()}


def _walk_json(node: Any, out: set[str]) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            key_low = str(key).lower()
            if key_low in IDENTITY_JSON_KEYS and val is not None:
                text = str(val).strip().lower()
                if text:
                    out.add(text)
                    if "@" in text:
                        out.add(text.split("@", 1)[0])
            _walk_json(val, out)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, out)


def identity_tokens_in_body(body: bytes | str | None) -> set[str]:
    raw = body if isinstance(body, bytes) else (body or "").encode("utf-8", errors="replace")
    if not raw:
        return set()
    text = raw.decode("utf-8", errors="replace").lower()
    found: set[str] = set()
    try:
        parsed = json.loads(text)
        _walk_json(parsed, found)
    except json.JSONDecodeError:
        pass
    emails = re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", text)
    found.update(emails)
    for email in emails:
        found.add(email.split("@", 1)[0])
    return {t for t in found if len(t) >= 2}


def tokens_present(body: bytes | str | None, tokens: set[str]) -> set[str]:
    if not tokens:
        return set()
    hay = identity_tokens_in_body(body)
    if not hay:
        text = (
            body.decode("utf-8", errors="replace").lower()
            if isinstance(body, bytes)
            else (body or "").lower()
        )
        return {t for t in tokens if t.lower() in text}
    return {t for t in tokens if t.lower() in hay}


def cross_account_leak_assessment(
    owner_body: bytes | str | None,
    other_body: bytes | str | None,
    owner_session: dict[str, Any],
    other_session: dict[str, Any],
    *,
    path: str = "",
    min_body_bytes: int = 48,
) -> tuple[bool, dict[str, Any]]:
    """True when other session received owner-identified data (not a generic shared payload)."""
    meta: dict[str, Any] = {"path": path}

    if is_cross_excluded_path(path):
        meta["reason"] = "excluded_path"
        return False, meta

    raw_owner = owner_body if isinstance(owner_body, bytes) else (owner_body or "").encode("utf-8", errors="replace")
    raw_other = other_body if isinstance(other_body, bytes) else (other_body or "").encode("utf-8", errors="replace")
    if len(raw_owner) < min_body_bytes or len(raw_other) < min_body_bytes:
        meta["reason"] = "body_too_small"
        return False, meta

    import hashlib

    owner_hash = hashlib.sha256(raw_owner).hexdigest()
    other_hash = hashlib.sha256(raw_other).hexdigest()
    meta["owner_body_sha256"] = owner_hash
    meta["other_body_sha256"] = other_hash
    if owner_hash != other_hash:
        meta["reason"] = "body_mismatch"
        return False, meta

    owner_tokens = session_identity_tokens(owner_session)
    other_tokens = session_identity_tokens(other_session)
    owner_in_body = tokens_present(owner_body, owner_tokens)
    other_in_body = tokens_present(other_body, other_tokens)

    meta["owner_tokens_in_body"] = sorted(owner_in_body)
    meta["other_tokens_in_body"] = sorted(other_in_body)

    if not owner_in_body:
        meta["reason"] = "generic_response_no_owner_identity"
        return False, meta

    # Other account auth returned a payload that still identifies the owner — cross leak.
    if owner_in_body:
        meta["reason"] = "owner_identity_in_shared_body"
        meta["leak_tokens"] = sorted(owner_in_body)
        return True, meta

    meta["reason"] = "no_leak"
    return False, meta
