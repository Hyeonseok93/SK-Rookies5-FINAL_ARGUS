"""Collect bases and login report for guideline 3-4."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.services.auth_probe_service import (
    build_login_entry_report,
    configured_login_entries,
    login_all_accounts,
)
from app.services.test_accounts_service import load_test_accounts
from diagnosis.replay.normalize import collect_probe_base_urls as collect_base_urls, filter_login_entry_report
from inventory.schema import ApiTree


def load_api_tree(data_dir: Path) -> ApiTree | None:
    for name in ("api-tree-verified.json", "api-tree-ready.json", "api-tree.json"):
        path = data_dir / name
        if path.is_file():
            return ApiTree.load(path)
    return None


def load_login_report(data_dir: Path, raw_config: dict[str, Any] | None) -> dict[str, Any] | None:
    verify_path = data_dir / "verify-report.json"
    if verify_path.is_file():
        try:
            raw = json.loads(verify_path.read_text(encoding="utf-8"))
            report = raw.get("login_entry_report")
            if isinstance(report, dict) and report.get("login_entries"):
                return filter_login_entry_report(report, raw_config)
        except (json.JSONDecodeError, OSError):
            pass

    auth_cfg = (raw_config or {}).get("auth") or {}
    entries = configured_login_entries(auth_cfg)
    if not entries:
        return None
    accounts = load_test_accounts().get("accounts") or []
    sessions = login_all_accounts(auth_cfg, accounts) if accounts else []
    return filter_login_entry_report(
        build_login_entry_report(auth_cfg, accounts, sessions),
        raw_config,
    )


def extra_admin_hosts_from_config(raw_config: dict[str, Any] | None) -> list[str]:
    from urllib.parse import urlparse

    cfg = (raw_config or {}).get("diagnosis_3_4") or {}
    hosts: list[str] = []
    for item in cfg.get("admin_hosts") or []:
        s = str(item).strip()
        if s:
            hosts.append(s.split(":")[0].lower())
    for url in cfg.get("admin_base_urls") or []:
        host = urlparse(str(url)).hostname
        if host:
            hosts.append(host.lower())
    return hosts
