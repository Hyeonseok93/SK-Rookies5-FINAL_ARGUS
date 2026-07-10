"""Account selection helpers for diagnosis 1-6."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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


def auto_role_login_targets(
    role_emails: list[str],
    raw_config: dict[str, Any] | None,
    data_dir: Path | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """
    role_login_targets/role_login_paths가 config에 명시돼 있지 않을 때만 호출되는
    fallback. 업로드된 api-tree에서 로그인 엔드포인트를 자동 탐지하는 기존
    login_discovery_service를 재사용해서, role 이메일의 로컬파트(예:
    "admin@travel.com" -> "admin")가 로그인 경로에 포함된 엔드포인트를 우선
    매칭한다. 애매하면 아무것도 채우지 않고 빈 dict를 돌려줘서, 호출부가 기존
    LOGIN_TARGET -> TARGET_URL fallback을 그대로 타게 한다 (틀린 값으로 덮어쓰지
    않음 — config에 명시값이 있으면 이 함수는 애초에 호출되지 않는다).
    """
    try:
        from app.services.login_discovery_service import resolve_login_entries
    except Exception:
        return {}, {}

    try:
        entries = resolve_login_entries(raw_config=raw_config, data_dir=data_dir)
    except Exception:
        return {}, {}
    if not entries:
        return {}, {}

    targets: dict[str, str] = {}
    paths: dict[str, str] = {}
    local_parts = {e.split("@", 1)[0].lower() for e in role_emails if e}

    def _apply(local_part: str, entry: dict[str, str]) -> None:
        parsed = urlparse(entry["url"])
        targets[local_part] = f"{parsed.scheme}://{parsed.netloc}"
        paths[local_part] = entry.get("path") or parsed.path

    matched_urls: set[str] = set()
    # 1순위: role 이름이 그대로 로그인 경로에 들어간 엔드포인트 (예: admin -> /admin/auth/login)
    for local_part in local_parts:
        if not local_part:
            continue
        for entry in entries:
            if local_part in entry.get("path", "").lower():
                _apply(local_part, entry)
                matched_urls.add(entry["url"])
                break

    # 2순위: 아직 못 찾은 role은 이름이 안 들어간 일반 로그인 엔드포인트를 공유
    remaining = [lp for lp in local_parts if lp and lp not in targets]
    if remaining:
        generic = next((e for e in entries if e["url"] not in matched_urls), entries[0])
        for local_part in remaining:
            _apply(local_part, generic)

    return targets, paths


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
