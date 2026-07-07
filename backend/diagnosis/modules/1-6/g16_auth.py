"""Account selection helpers for diagnosis 1-6."""

from __future__ import annotations

from typing import Any

from app.services.test_accounts_service import load_test_accounts


def roles_from_config(cfg: dict[str, Any]) -> list[str]:
    raw_roles = cfg.get("roles")
    if isinstance(raw_roles, list):
        roles: list[str] = []
        for item in raw_roles:
            if isinstance(item, str) and ":" in item:
                roles.append(item)
            elif isinstance(item, dict) and item.get("email") and item.get("password"):
                roles.append(f"{item['email']}:{item['password']}")
        if roles:
            return roles

    accounts = load_test_accounts().get("accounts") or []
    return [
        f"{account['email']}:{account['password']}"
        for account in accounts
        if account.get("email") and account.get("password")
    ]


def redact_roles(args: list[str]) -> list[str]:
    redacted: list[str] = []
    in_roles = False
    for arg in args:
        if arg == "--roles":
            in_roles = True
            redacted.append(arg)
            continue
        if in_roles and arg.startswith("--"):
            in_roles = False
        if in_roles and ":" in arg:
            redacted.append(arg.split(":", 1)[0] + ":***")
        else:
            redacted.append(arg)
    return redacted
