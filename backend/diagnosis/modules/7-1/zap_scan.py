"""ZAP active scan for guideline 7-1 insecure HTTP methods (Rule 90028)."""

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

# 7-1 scope: insecure HTTP method policy only.
SCANNER_RULES: tuple[tuple[int, str, str], ...] = (
    (90028, "Medium", "Low"),  # Insecure HTTP Method
)

PLUGIN_LABELS: dict[str, str] = {
    "90028": "ZAP Rule 90028 (Insecure HTTP Method)",
    "90028-1": "ZAP Rule 90028-1 (PUT method enabled)",
    "90028-2": "ZAP Rule 90028-2 (POST method overridden)",
    "90028-3": "ZAP Rule 90028-3 (TRACE method enabled)",
    "90028-4": "ZAP Rule 90028-4 (OPTIONS method enabled)",
    "90028-5": "ZAP Rule 90028-5 (CONNECT method enabled)",
    "90028-6": "ZAP Rule 90028-6 (DELETE method enabled)",
}

PLUGIN_SEVERITY: dict[str, str] = {
    "90028-3": "high",
    "90028-5": "high",
    "90028-1": "low",
    "90028-6": "low",
}


def is_71_method_plugin(plugin_id: str) -> bool:
    pid = str(plugin_id or "").strip()
    return pid == "90028" or pid.startswith("90028-")


def configure_71_scanners(zap: Any) -> None:
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


def _severity_from_alert(plugin_id: str, risk: str) -> str:
    if plugin_id in PLUGIN_SEVERITY:
        return PLUGIN_SEVERITY[plugin_id]
    level = str(risk or "Low").strip().lower()
    if level == "high":
        return "high"
    if level == "medium":
        return "medium"
    return "low"


def _infer_issue_type(plugin_id: str, alert_name: str) -> str:
    pid = str(plugin_id)
    name = alert_name.lower()
    if pid == "90028-3" or "trace" in name:
        return "trace_enabled"
    if pid == "90028-6" or "delete" in name:
        return "delete_enabled"
    if pid == "90028-1" or "put" in name:
        return "put_enabled"
    if pid == "90028-5" or "connect" in name:
        return "connect_enabled"
    if pid == "90028-4" or "options" in name:
        return "options_enabled"
    return "insecure_method"


def zap_alert_to_finding(alert: dict[str, Any], *, base_url: str) -> DiagnosisFinding | None:
    plugin_id = str(alert.get("pluginId", ""))
    if not is_71_method_plugin(plugin_id):
        return None
    severity = _severity_from_alert(plugin_id, str(alert.get("risk", "Low")))
    url = str(alert.get("url") or "")
    name = str(alert.get("alert") or alert.get("name") or "ZAP insecure HTTP method")
    issue_type = _infer_issue_type(plugin_id, name)
    return DiagnosisFinding(
        severity=severity,
        message=f"[7-1] ZAP insecure HTTP method: {name} at `{url}`",
        evidence={
            "rule_id": "7-1-insecure-http-method",
            "source": "zap",
            "engine": "zap",
            "issue_type": issue_type,
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


def collect_zap_method_findings(zap: Any, base_urls: list[str]) -> list[DiagnosisFinding]:
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
    """Returns (findings, stats). Raises ZapNotAvailableError if ZAP required but missing."""
    zap_cfg = raw_config.get("zap") or {}
    scan_cfg = raw_config.get("diagnosis_7_1") or raw_config.get("scan_7_1") or {}
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped"}

    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)
    stats: dict[str, Any] = {"zap_proxy": proxy, "mode": "active_90028"}
    findings: list[DiagnosisFinding] = []
    try:
        stats["workspace_reset_before"] = reset_zap_workspace(zap, session_name="argus-g71-start")
        apply_auth_to_zap(zap, auth)
        configure_71_scanners(zap)

        seed_urls = select_seed_urls(
            probe_targets,
            seed_cap,
            priority_urls=priority_seed_urls,
        )
        seeded = seed_probe_urls(zap, seed_urls)
        passive_remaining = wait_for_passive_scan(zap)
        scan_ids = active_scan_bases(zap, base_urls, max_minutes=max_minutes)
        findings = collect_zap_method_findings(zap, base_urls)
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
            stats["workspace_reset_after"] = reset_zap_workspace(zap, session_name="argus-g71-done")
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    return findings, stats
