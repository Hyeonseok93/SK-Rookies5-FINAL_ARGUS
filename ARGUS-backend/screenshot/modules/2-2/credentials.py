"""Load replay credentials supplied by the diagnosis workflow."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ReplayCredential:
    account_id: str
    identifier: str
    password: str


def _decrypt_password(value: str) -> str:
    if not value:
        return ""
    try:
        from app.credentials_crypto import decrypt_secret

        return decrypt_secret(value)
    except Exception:
        return value


def load_replay_credentials(data_dir: Path) -> list[ReplayCredential]:
    path = data_dir / "test-accounts.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    credentials: list[ReplayCredential] = []
    for index, row in enumerate(payload.get("accounts") or []):
        identifier = str(row.get("email") or row.get("username") or row.get("id_value") or "")
        password = _decrypt_password(str(row.get("password") or ""))
        if identifier and password:
            credentials.append(
                ReplayCredential(
                    account_id=str(row.get("id") or f"account-{index + 1}"),
                    identifier=identifier,
                    password=password,
                )
            )
    return credentials
