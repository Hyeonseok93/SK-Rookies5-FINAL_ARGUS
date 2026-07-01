"""ZAP passive scan for guideline 7-4 weak security configuration."""

from __future__ import annotations

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

# 7-4 scope: missing/weak security headers and cookies (passive only).
SECURITY_PLUGIN_IDS: frozenset[str] = frozenset(
    {"10035", "10038", "10020", "10021", "10054", "10063"}
)

PLUGIN_LABELS: dict[str, str] = {
    "10035": "ZAP Rule 10035 (HSTS not set)",
    "10038": "ZAP Rule 10038 (CSP not set)",
    "10020": "ZAP Rule 10020 (X-Frame-Options)",
    "10021": "ZAP Rule 10021 (X-Content-Type-Options)",
    "10054": "ZAP Rule 10054 (Cookie without Secure)",
    "10063": "ZAP Rule 10063 (Permissions-Policy)",
}


def is_74_security_plugin(plugin_id: str) -> bool:
    return str(plugin_id or "").strip() in SECURITY_PLUGIN_IDS


def configure_74_scanners(zap: Any) -> None:
    zap.ascan.disable_all_scanners()


def _infer_check_type(plugin_id: str, alert_name: str) -> tuple[str, str | None]:
    pid = str(plugin_id)
    name = alert_name.lower()
    mapping = {
        "10035": ("missing_hsts", "strict-transport-security"),
        "10038": ("missing_csp", "content-security-policy"),
        "10020": ("missing_x_frame_options", "x-frame-options"),
        "10021": ("missing_nosniff", "x-content-type-options"),
        "10054": ("cookie_missing_secure", "set-cookie"),
        "10063": ("missing_permissions_policy", "permissions-policy"),
    }
    if pid in mapping:
        return mapping[pid]
    if "hsts" in name or "strict-transport" in name:
        return "missing_hsts", "strict-transport-security"
    if "csp" in name or "content-security" in name:
        return "missing_csp", "content-security-policy"
    if "frame" in name:
        return "missing_x_frame_options", "x-frame-options"
    if "content-type" in name or "nosniff" in name:
        return "missing_nosniff", "x-content-type-options"
    if "cookie" in name:
        return "cookie_missing_secure", "set-cookie"
    return "weak_security_config", None


def _severity_from_risk(risk: str) -> str:
    level = str(risk or "Low").strip().lower()
    if level == "high":
        return "high"
    if level == "medium":
        return "medium"
    return "low"


def zap_alert_to_finding(alert: dict[str, Any], *, base_url: str) -> DiagnosisFinding | None:
    plugin_id = str(alert.get("pluginId", ""))
    if not is_74_security_plugin(plugin_id):
        return None
    severity = _severity_from_risk(str(alert.get("risk", "Low")))
    url = str(alert.get("url") or "")
    name = str(alert.get("alert") or alert.get("name") or "ZAP weak security config")
    check_type, header = _infer_check_type(plugin_id, name)
    evidence_val = str(alert.get("evidence") or alert.get("other") or "").strip()
    return DiagnosisFinding(
        severity=severity,
        message=f"[7-4] ZAP weak security config: {name} at `{url}`",
        evidence={
            "rule_id": "7-4-weak-security",
            "source": "zap",
            "engine": "zap",
            "check_type": check_type,
            "header": header,
            "header_value": evidence_val or None,
            "reason": name,
            "plugin_id": plugin_id,
            "url": url,
            "label": url,
            "base_url": base_url,
            "param": alert.get("param"),
            "risk": alert.get("risk"),
            "trigger": f"zap_rule_{plugin_id}",
            "trigger_label": PLUGIN_LABELS.get(plugin_id, f"ZAP Rule {plugin_id}"),
        },
    )


def collect_zap_security_findings(zap: Any, base_urls: list[str]) -> list[DiagnosisFinding]:
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
            dedupe = f"{ev.get('plugin_id')}:{ev.get('url')}:{ev.get('check_type')}"
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
    max_minutes: int = 10,
    seed_cap: int = 200,
    priority_seed_urls: list[str] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    zap_cfg = raw_config.get("zap") or {}
    scan_cfg = raw_config.get("diagnosis_7_4") or raw_config.get("scan_7_4") or {}
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped"}

    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)
    stats: dict[str, Any] = {"zap_proxy": proxy, "mode": "passive_only"}
    findings: list[DiagnosisFinding] = []
    passive_wait = max(30, min(max_minutes * 60, 600))
    try:
        stats["workspace_reset_before"] = reset_zap_workspace(zap, session_name="argus-g74-start")
        apply_auth_to_zap(zap, auth)
        configure_74_scanners(zap)

        seed_urls = select_seed_urls(
            probe_targets,
            seed_cap,
            priority_urls=priority_seed_urls,
        )
        seeded = seed_probe_urls(zap, seed_urls)
        passive_remaining = wait_for_passive_scan(zap, max_seconds=passive_wait)
        findings = collect_zap_security_findings(zap, base_urls)
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
            stats["workspace_reset_after"] = reset_zap_workspace(zap, session_name="argus-g74-done")
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    return findings, stats
