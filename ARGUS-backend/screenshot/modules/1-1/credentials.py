"""Saved test account loader for 1-1 CSRF evidence replay.

Reads the current workspace ``test-accounts.json`` (prefer ``ARGUS_DATA_DIR``).
Encrypted ``enc:`` passwords are decrypted when the crypto helper is available.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ReplayCredential:
    role: str
    email: str
    password: str


def _data_dir() -> Path:
    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    if env:
        return Path(env)
    # Docker: /app/screenshot/modules/1-1/credentials.py -> /app/data (legacy fallback)
    return Path(__file__).resolve().parents[3] / "data"


def _decrypt_password(value: str) -> str:
    if not value:
        return ""
    try:
        from app.credentials_crypto import decrypt_secret

        return decrypt_secret(value)
    except Exception:
        return value


def _normalize_role(value: str | None) -> str:
    return str(value or "").strip().lower().replace("role_", "")


def saved_credentials_for_role(role: str | None) -> list[ReplayCredential]:
    """Load saved frontend test accounts, preferring optional matching role."""
    wanted = _normalize_role(role)
    path = _data_dir() / "test-accounts.json"
    if not path.is_file():
        return []

    raw = json.loads(path.read_text(encoding="utf-8"))
    rows: list[tuple[str, ReplayCredential]] = []
    for account in raw.get("accounts") or []:
        if not isinstance(account, dict):
            continue
        email = str(account.get("email") or "").strip()
        password = _decrypt_password(str(account.get("password") or ""))
        if not email or not password:
            continue
        account_role = _normalize_role(
            account.get("role") or account.get("account_role") or account.get("type")
        )
        rows.append(
            (
                account_role,
                ReplayCredential(
                    role=account_role or "account",
                    email=email,
                    password=password,
                ),
            )
        )

    if not wanted:
        return [credential for _, credential in rows]

    preferred = [credential for account_role, credential in rows if account_role == wanted]
    fallback = [credential for account_role, credential in rows if account_role != wanted]
    return preferred + fallback
