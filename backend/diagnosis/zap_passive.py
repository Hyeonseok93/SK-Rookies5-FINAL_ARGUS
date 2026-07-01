"""Shared passive-only ZAP scan orchestration for 7-x modules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from integrations.zap.client import (
    apply_auth_to_zap,
    connect_zap,
    ensure_zap_proxy,
    reset_zap_workspace,
    seed_probe_urls,
    select_seed_urls,
    wait_for_passive_scan,
)
from diagnosis.result import DiagnosisFinding


def run_passive_zap_phase(
    raw_config: dict[str, Any],
    probe_targets: list[dict[str, str]],
    base_urls: list[str],
    auth: dict[str, Any] | None,
    *,
    scan_cfg_keys: tuple[str, ...],
    session_prefix: str,
    configure_scanners: Callable[[Any], None],
    collect_findings: Callable[[Any, list[str]], list[DiagnosisFinding]],
    max_minutes: int = 10,
    seed_cap: int = 200,
    priority_seed_urls: list[str] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    zap_cfg = raw_config.get("zap") or {}
    scan_cfg: dict[str, Any] = {}
    for key in scan_cfg_keys:
        block = raw_config.get(key)
        if isinstance(block, dict):
            scan_cfg.update(block)
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped"}

    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)
    stats: dict[str, Any] = {"zap_proxy": proxy, "mode": "passive_only"}
    findings: list[DiagnosisFinding] = []
    passive_wait = max(30, min(max_minutes * 60, 600))
    try:
        stats["workspace_reset_before"] = reset_zap_workspace(
            zap, session_name=f"{session_prefix}-start"
        )
        apply_auth_to_zap(zap, auth)
        configure_scanners(zap)

        seed_urls = select_seed_urls(
            probe_targets,
            seed_cap,
            priority_urls=priority_seed_urls,
        )
        seeded = seed_probe_urls(zap, seed_urls)
        passive_remaining = wait_for_passive_scan(zap, max_seconds=passive_wait)
        findings = collect_findings(zap, base_urls)
        stats.update(
            {
                "seeded": seeded,
                "seed_cap": seed_cap,
                "seed_candidates": len(seed_urls),
                "priority_seeded": len(priority_seed_urls or []),
                "passive_wait_seconds": passive_wait,
                "passive_remaining": passive_remaining,
                "alerts": len(findings),
            }
        )
    finally:
        try:
            stats["workspace_reset_after"] = reset_zap_workspace(
                zap, session_name=f"{session_prefix}-done"
            )
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    return findings, stats
