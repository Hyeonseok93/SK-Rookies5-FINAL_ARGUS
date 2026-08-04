from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from app.credentials_crypto import decrypt_secret, encrypt_secret, mask_secret
from app.workspace import require_data_dir

MASKED = "********"


def _accounts_path(data_dir: Path) -> Path:
    return data_dir / "test-accounts.json"


def load_test_accounts(
    data_dir: Path | None = None,
    *,
    mask: bool = False,
) -> dict[str, Any]:
    """Load accounts for the bound/user workspace.

    By default returns decrypted passwords for diagnosis/login probes.
    Pass ``mask=True`` for API responses.
    """
    data_dir = require_data_dir(data_dir)
    accounts: list[dict[str, str]] = []
    path = _accounts_path(data_dir)
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        for entry in raw.get("accounts", []):
            email = str(entry.get("email", "")).strip()
            password = str(entry.get("password", ""))
            entry_id = str(entry.get("id") or "").strip() or uuid.uuid4().hex
            if not email and not password:
                continue
            plain = decrypt_secret(password)
            accounts.append(
                {
                    "id": entry_id,
                    "email": email,
                    "password": mask_secret(plain) if mask else plain,
                }
            )
    return {"accounts": accounts}


def save_test_accounts(data_dir: Path | None, accounts: list[dict[str, str]]) -> dict[str, Any]:
    data_dir = require_data_dir(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    existing = {
        a["id"]: a
        for a in load_test_accounts(data_dir, mask=False).get("accounts", [])
    }
    normalized: list[dict[str, str]] = []

    for entry in accounts:
        email = str(entry.get("email", "")).strip()
        password = str(entry.get("password", ""))
        entry_id = str(entry.get("id") or "").strip() or uuid.uuid4().hex
        if not email and not password:
            continue
        if (not password or password == MASKED) and entry_id in existing:
            password = existing[entry_id]["password"]
        if not email and not password:
            continue
        normalized.append(
            {
                "id": entry_id,
                "email": email,
                "password": encrypt_secret(password) if password else "",
            }
        )

    payload = {"accounts": normalized}
    _accounts_path(data_dir).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return load_test_accounts(data_dir, mask=True)
