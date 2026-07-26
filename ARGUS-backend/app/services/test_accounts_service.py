from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
TEST_ACCOUNTS_PATH = DATA_DIR / "test-accounts.json"


def _normalize_entry(raw: dict[str, Any]) -> dict[str, str] | None:
    email = str(raw.get("email", "")).strip()
    password = str(raw.get("password", ""))
    entry_id = str(raw.get("id") or "").strip() or uuid.uuid4().hex

    if not email and not password:
        return None

    return {
        "id": entry_id,
        "email": email,
        "password": password,
    }


def load_test_accounts() -> dict[str, Any]:
    accounts: list[dict[str, str]] = []
    if TEST_ACCOUNTS_PATH.is_file():
        raw = json.loads(TEST_ACCOUNTS_PATH.read_text(encoding="utf-8"))
        for entry in raw.get("accounts", []):
            normalized = _normalize_entry(entry)
            if normalized:
                accounts.append(normalized)
    return {"accounts": accounts}


def save_test_accounts(accounts: list[dict[str, str]]) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    normalized: list[dict[str, str]] = []

    for entry in accounts:
        item = _normalize_entry(entry)
        if item:
            normalized.append(item)

    payload = {"accounts": normalized}
    TEST_ACCOUNTS_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return load_test_accounts()
