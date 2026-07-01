"""ZAP scan for guideline 7-2 directory listing (active Rule 0 + passive 10033)."""

from __future__ import annotations

import time
from typing import Any

from app.services.zap_util import (
    ZapNotAvailableError,
    apply_auth_to_zap,
    connect_zap,
    ensure_zap_proxy,
    probe_url,
    reset_zap_workspace,
    seed_probe_urls,
    select_seed_urls,
    wait_for_passive_scan,
)
from diagnosis.result import DiagnosisFinding

# 7-2 scope: directory browsing only (not 2-2 traversal / hidden file rules).
SCANNER_RULES: tuple[tuple[int, str, str], ...] = (
    (0, "Medium", "Medium"),  # Directory Browsing
)

ALERT_RULE_MAP: dict[str, tuple[str, str]] = {
    "0": ("medium", "7-2-directory-listing"),
    "10033": ("medium", "7-2-directory-listing"),  # passive Directory Browsing (Index of /…)
}

PLUGIN_LABELS: dict[str, str] = {
    "0": "ZAP Rule 0 (Directory Browsing, active)",
    "10033": "ZAP Rule 10033 (Directory Browsing, passive)",
}


def configure_72_scanners(zap: Any) -> None:
    zap.ascan.disable_all_scanners()
    for rule_id, threshold, strength in SCANNER_RULES:
        rid = str(rule_id)
        zap.ascan.enable_scanners(rid)
        zap.ascan.set_scanner_alert_threshold(rid, threshold)
        zap.ascan.set_scanner_attack_strength(rid, strength)


def active_scan_bases(
    zap: Any,
    base_urls: list[str],
    *,
    max_minutes: int = 15,
) -> list[str]:
    scan_ids: list[str] = []
    for base in base_urls:
        try:
            sid = zap.ascan.scan(url=probe_url(base.rstrip("/")), recurse=True, scanpolicyname="")
            if sid:
                scan_ids.append(str(sid))
        except Exception:
            continue

    deadline = time.time() + max_minutes * 60
    while time.time() < deadline:
        pending = 0
        for sid in scan_ids:
            try:
                progress = int(zap.ascan.status(sid))
            except Exception:
                continue
            if progress < 100:
                pending += 1
        if pending == 0:
            break
        time.sleep(2)
    return scan_ids


def zap_alert_to_finding(alert: dict[str, Any], *, base_url: str) -> DiagnosisFinding | None:
    plugin_id = str(alert.get("pluginId", ""))
    if plugin_id not in ALERT_RULE_MAP:
        return None
    severity, rule_id = ALERT_RULE_MAP[plugin_id]
    url = str(alert.get("url") or "")
    name = str(alert.get("alert") or alert.get("name") or "ZAP directory browsing")
    listing_type = "zap_passive_directory_browsing" if plugin_id == "10033" else "zap_directory_browsing"
    return DiagnosisFinding(
        severity=severity,
        message=f"[7-2] ZAP directory browsing: {name} at `{url}`",
        evidence={
            "rule_id": rule_id,
            "listing_type": listing_type,
            "source": "zap",
            "engine": "zap",
            "reason": name,
            "plugin_id": plugin_id,
            "url": url,
            "label": url,
            "base_url": base_url,
            "param": alert.get("param"),
            "risk": alert.get("risk"),
            "evidence": alert.get("evidence"),
            "trigger": f"zap_rule_{plugin_id}",
            "trigger_label": PLUGIN_LABELS.get(plugin_id, f"ZAP Rule {plugin_id}"),
        },
    )


def collect_zap_listing_findings(zap: Any, base_urls: list[str]) -> list[DiagnosisFinding]:
    findings: list[DiagnosisFinding] = []
    seen: set[str] = set()

    for base in base_urls:
        try:
            alerts = zap.core.alerts(baseurl=probe_url(base.rstrip("/")))
        except Exception:
            alerts = []
        for alert in alerts or []:
            if not isinstance(alert, dict):
                continue
            finding = zap_alert_to_finding(alert, base_url=base)
            if finding is None:
                continue
            ev = finding.evidence or {}
            dedupe = f"{ev.get('plugin_id')}:{ev.get('url')}:{ev.get('param')}"
            if dedupe in seen:
                continue
            seen.add(dedupe)
            findings.append(finding)
    return findings


def run_zap_phase(
    raw_config: dict[str, Any],
    probe_targets: list[dict[str, str]],
    base_urls: list[str],
    auth: dict[str, Any] | None,
    *,
    max_minutes: int = 15,
    seed_cap: int = 300,
    priority_seed_urls: list[str] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """Returns (findings, stats). Raises ZapNotAvailableError if ZAP required but missing."""
    zap_cfg = raw_config.get("zap") or {}
    scan_cfg = raw_config.get("diagnosis_7_2") or raw_config.get("scan_7_2") or {}
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped"}

    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)
    stats: dict[str, Any] = {"zap_proxy": proxy}
    findings: list[DiagnosisFinding] = []
    try:
        stats["workspace_reset_before"] = reset_zap_workspace(zap, session_name="argus-g72-start")
        apply_auth_to_zap(zap, auth)

        configure_72_scanners(zap)
        seed_urls = select_seed_urls(
            probe_targets,
            seed_cap,
            priority_urls=priority_seed_urls,
        )
        seeded = seed_probe_urls(zap, seed_urls)
        passive_remaining = wait_for_passive_scan(zap)
        scan_ids = active_scan_bases(zap, base_urls, max_minutes=max_minutes)
        findings = collect_zap_listing_findings(zap, base_urls)
        stats.update(
            {
                "seeded": seeded,
                "seed_cap": seed_cap,
                "seed_candidates": len(seed_urls),
                "priority_seeded": len(priority_seed_urls or []),
                "passive_remaining": passive_remaining,
                "active_scans": len(scan_ids),
                "alerts": len(findings),
            }
        )
    finally:
        try:
            stats["workspace_reset_after"] = reset_zap_workspace(zap, session_name="argus-g72-done")
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    return findings, stats
