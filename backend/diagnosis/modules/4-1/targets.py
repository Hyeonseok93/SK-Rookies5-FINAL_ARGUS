"""Targets and sessions for guideline 4-1 cookie probes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from app.services.auth_probe_service import (
    build_login_entry_report,
    configured_login_entries,
    login_all_accounts,
)
from app.services.test_accounts_service import load_test_accounts
from app.services.zap_util import probe_url
from diagnosis.probe_auth import all_account_auths_with_meta
from diagnosis.replay.normalize import filter_endpoints_by_probe_bases, filter_login_entry_report
from inventory.schema import ApiTree, Endpoint
from inventory.load import load_api_tree

ProbeMode = Literal["base_only", "sample", "full"]



def load_login_report(data_dir: Path, raw_config: dict[str, Any] | None) -> dict[str, Any] | None:
    verify_path = data_dir / "verify-report.json"
    if verify_path.is_file():
        try:
            raw = json.loads(verify_path.read_text(encoding="utf-8"))
            report = raw.get("login_entry_report")
            if isinstance(report, dict):
                return filter_login_entry_report(report, raw_config)
        except (json.JSONDecodeError, OSError):
            pass

    auth_cfg = (raw_config or {}).get("auth") or {}
    accounts = load_test_accounts().get("accounts") or []
    entries = configured_login_entries(auth_cfg)
    if not entries or not accounts:
        return None
    sessions = login_all_accounts(auth_cfg, accounts)
    return filter_login_entry_report(
        build_login_entry_report(auth_cfg, accounts, sessions),
        raw_config,
    )


def load_sessions(
    raw_config: dict[str, Any] | None, data_dir: Path | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return all_account_auths_with_meta(raw_config, data_dir=data_dir)


def collect_probe_endpoints(
    tree: ApiTree | None,
    *,
    raw_config: dict[str, Any] | None = None,
    probe_mode: ProbeMode,
    sample_size: int,
    max_endpoints: int,
    is_candidate_fn: Any,
) -> list[Endpoint]:
    if tree is None or probe_mode == "base_only":
        return []

    scoped = filter_endpoints_by_probe_bases(tree.endpoints, raw_config)

    admin: list[Endpoint] = []
    other: list[Endpoint] = []
    for ep in scoped:
        if ep.method.upper() not in ("GET", "HEAD"):
            continue
        if not is_candidate_fn(ep.path, ep=ep):
            continue
        if "/admin" in (ep.path or "").lower() or "/api/v1/admin" in (ep.path or "").lower():
            admin.append(ep)
        else:
            other.append(ep)

    admin.sort(key=lambda e: e.endpoint_id)
    other.sort(key=lambda e: e.endpoint_id)

    if probe_mode == "full":
        picked = admin + other
    else:
        step = max(1, len(other) // max(sample_size, 1)) if other else 1
        picked = admin + other[::step][:sample_size]

    seen: set[str] = set()
    out: list[Endpoint] = []
    for ep in picked:
        if ep.endpoint_id in seen:
            continue
        seen.add(ep.endpoint_id)
        out.append(ep)
        if len(out) >= max_endpoints:
            break
    return out


def probe_base(url: str) -> str:
    return probe_url(url.rstrip("/"))
