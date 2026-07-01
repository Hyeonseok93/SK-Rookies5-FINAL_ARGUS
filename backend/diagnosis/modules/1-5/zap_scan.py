"""ZAP active scan for guideline 1-5 open redirect (Rules 40031, 10028)."""

from __future__ import annotations

import time
from typing import Any

from app.services.zap_util import (
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

OPEN_REDIRECT_PLUGIN_IDS: frozenset[str] = frozenset({"40031", "10028"})

PLUGIN_LABELS: dict[str, str] = {
    "40031": "ZAP Rule 40031 (URL Redirection to Untrusted Site)",
    "10028": "ZAP Rule 10028 (Open Redirect)",
}


def is_15_redirect_plugin(plugin_id: str) -> bool:
    pid = str(plugin_id or "").strip()
    return pid in OPEN_REDIRECT_PLUGIN_IDS


def configure_15_scanners(zap: Any) -> None:
    zap.ascan.disable_all_scanners()
    for rid in sorted(OPEN_REDIRECT_PLUGIN_IDS):
        zap.ascan.enable_scanners(rid)
        zap.ascan.set_scanner_alert_threshold(rid, "Medium")
        zap.ascan.set_scanner_attack_strength(rid, "High")


def active_scan_bases(
    zap: Any,
    base_urls: list[str],
    *,
    max_minutes: int = 15,
) -> list[str]:
    scan_ids: list[str] = []
    for base in base_urls:
        try:
            sid = zap.ascan.scan(url=probe_url(base.rstrip("/")), recurse=False, scanpolicyname="")
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


def _severity_from_risk(risk: str) -> str:
    level = str(risk or "Low").strip().lower()
    if level == "high":
        return "high"
    if level == "medium":
        return "medium"
    return "low"


def zap_alert_to_finding(alert: dict[str, Any], *, base_url: str) -> DiagnosisFinding | None:
    plugin_id = str(alert.get("pluginId", ""))
    if not is_15_redirect_plugin(plugin_id):
        return None
    severity = _severity_from_risk(str(alert.get("risk", "Medium")))
    url = str(alert.get("url") or "")
    name = str(alert.get("alert") or alert.get("name") or "ZAP open redirect")
    return DiagnosisFinding(
        severity=severity,
        message=f"[1-5] ZAP open redirect: {name} at `{url}`",
        evidence={
            "rule_id": "1-5-open-redirect",
            "source": "zap",
            "engine": "zap",
            "trigger": f"zap_rule_{plugin_id}",
            "trigger_label": PLUGIN_LABELS.get(plugin_id, f"ZAP Rule {plugin_id}"),
            "plugin_id": plugin_id,
            "url": url,
            "label": url,
            "base_url": base_url,
            "param": alert.get("param"),
            "risk": alert.get("risk"),
            "evidence": alert.get("evidence"),
            "related_sections": ["1-5"],
        },
    )


def collect_zap_redirect_findings(zap: Any, base_urls: list[str]) -> list[DiagnosisFinding]:
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
    seed_cap: int = 200,
    priority_seed_urls: list[str] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    zap_cfg = raw_config.get("zap") or {}
    scan_cfg = raw_config.get("diagnosis_1_5") or raw_config.get("scan_1_5") or {}
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped"}

    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)
    stats: dict[str, Any] = {"zap_proxy": proxy, "mode": "active_open_redirect"}
    findings: list[DiagnosisFinding] = []
    try:
        stats["workspace_reset_before"] = reset_zap_workspace(zap, session_name="argus-g15-start")
        apply_auth_to_zap(zap, auth)
        configure_15_scanners(zap)

        seed_urls = select_seed_urls(
            probe_targets,
            seed_cap,
            priority_urls=priority_seed_urls,
        )
        seeded = seed_probe_urls(zap, seed_urls)
        passive_remaining = wait_for_passive_scan(zap)
        scan_ids = active_scan_bases(zap, base_urls, max_minutes=max_minutes)
        findings = collect_zap_redirect_findings(zap, base_urls)
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
            stats["workspace_reset_after"] = reset_zap_workspace(zap, session_name="argus-g15-done")
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    return findings, stats
