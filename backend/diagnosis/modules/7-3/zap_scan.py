"""ZAP passive scan for guideline 7-3 server header disclosure."""

from __future__ import annotations

from typing import Any

from app.services.zap_util import probe_url
from diagnosis.result import DiagnosisFinding
from diagnosis.zap_passive import run_passive_zap_phase
from diagnosis.zap_passive import run_passive_zap_phase

# 7-3 scope: response header disclosure only (passive rules).
HEADER_PLUGIN_IDS: frozenset[str] = frozenset({"10036", "10037"})

PLUGIN_LABELS: dict[str, str] = {
    "10036": "ZAP Rule 10036 (Server header disclosure)",
    "10037": "ZAP Rule 10037 (X-Powered-By disclosure)",
    "10036-1": "ZAP Rule 10036-1 (Server application leak)",
    "10036-2": "ZAP Rule 10036-2 (Server version leak)",
}


def is_73_header_plugin(plugin_id: str) -> bool:
    pid = str(plugin_id or "").strip()
    return pid in HEADER_PLUGIN_IDS or pid.startswith("10036-")


def configure_73_scanners(zap: Any) -> None:
    """7-3 uses passive header rules only — keep all active scanners disabled."""
    zap.ascan.disable_all_scanners()


def _infer_header(plugin_id: str, alert_name: str) -> str:
    pid = str(plugin_id)
    if pid == "10037" or "x-powered-by" in alert_name.lower():
        return "x-powered-by"
    if pid.startswith("10036") or "server" in alert_name.lower():
        return "server"
    return "unknown"


def _severity_from_risk(risk: str) -> str:
    level = str(risk or "Low").strip().lower()
    if level in ("high", "medium"):
        return "medium"
    return "low"


def zap_alert_to_finding(alert: dict[str, Any], *, base_url: str) -> DiagnosisFinding | None:
    plugin_id = str(alert.get("pluginId", ""))
    if not is_73_header_plugin(plugin_id):
        return None
    severity = _severity_from_risk(str(alert.get("risk", "Low")))
    url = str(alert.get("url") or "")
    name = str(alert.get("alert") or alert.get("name") or "ZAP header disclosure")
    header = _infer_header(plugin_id, name)
    header_value = str(alert.get("evidence") or alert.get("other") or "").strip()
    return DiagnosisFinding(
        severity=severity,
        message=f"[7-3] ZAP header disclosure: {name} at `{url}`",
        evidence={
            "rule_id": "7-3-header-disclosure",
            "source": "zap",
            "engine": "zap",
            "header": header,
            "header_value": header_value or name,
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


def collect_zap_header_findings(zap: Any, base_urls: list[str]) -> list[DiagnosisFinding]:
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
            dedupe = f"{ev.get('plugin_id')}:{ev.get('url')}:{ev.get('header')}"
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
    """Returns (findings, stats). Raises ZapNotAvailableError if ZAP required but missing."""
    return run_passive_zap_phase(
        raw_config,
        probe_targets,
        base_urls,
        auth,
        scan_cfg_keys=("diagnosis_7_3", "scan_7_3"),
        session_prefix="argus-g73",
        configure_scanners=configure_73_scanners,
        collect_findings=collect_zap_header_findings,
        max_minutes=max_minutes,
        seed_cap=seed_cap,
        priority_seed_urls=priority_seed_urls,
    )
