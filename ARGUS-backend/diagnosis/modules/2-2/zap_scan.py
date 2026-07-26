"""ZAP integration for guideline 2-2 — unified probes + supplemental native scan."""

from __future__ import annotations

import importlib.util
import time
from pathlib import Path
from typing import Any

from app.services.zap_util import (
    apply_auth_to_zap,
    connect_zap,
    ensure_zap_proxy,
    probe_url,
    reset_zap_workspace,
)
from diagnosis.result import DiagnosisFinding
from inventory.net import probe_base_url

_MODULE_DIR = Path(__file__).resolve().parent

# Supplemental only — core 2-2 checks use unified ARGUS logic via ZapTransport.
SUPPLEMENTAL_SCANNER_RULES: tuple[tuple[int, str, str], ...] = (
    (0, "Medium", "Medium"),  # Directory Browsing
    (40035, "Medium", "Medium"),  # Hidden File Finder
    (40034, "Medium", "Low"),  # .env
    (40032, "Medium", "Low"),  # .htaccess
)

SUPPLEMENTAL_ALERT_RULE_MAP: dict[str, tuple[str, str]] = {
    "0": ("medium", "2-2-directory-browsing"),
    "10033": ("medium", "2-2-directory-listing"),
    "40035": ("high", "2-2-hidden-file"),
    "40034": ("high", "2-2-env-leak"),
    "40032": ("medium", "2-2-htaccess-leak"),
}

PLUGIN_LABELS: dict[str, str] = {
    "0": "ZAP Rule 0 (Directory Browsing, active)",
    "10033": "ZAP Rule 10033 (Directory Browsing, passive)",
    "40035": "ZAP Rule 40035 (Hidden File Finder)",
    "40034": "ZAP Rule 40034 (.env Information Leak)",
    "40032": "ZAP Rule 40032 (.htaccess Information Leak)",
}


def _load_runner():
    spec = importlib.util.spec_from_file_location("diag_g22_runner_zap", _MODULE_DIR / "runner.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load runner")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["diag_g22_runner_zap"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_transport():
    spec = importlib.util.spec_from_file_location("diag_g22_transport_zap", _MODULE_DIR / "transport.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load transport")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["diag_g22_transport_zap"] = mod
    spec.loader.exec_module(mod)
    return mod


def configure_22_supplemental_scanners(zap: Any) -> None:
    zap.ascan.disable_all_scanners()
    for rule_id, threshold, strength in SUPPLEMENTAL_SCANNER_RULES:
        rid = str(rule_id)
        zap.ascan.enable_scanners(rid)
        zap.ascan.set_scanner_alert_threshold(rid, threshold)
        zap.ascan.set_scanner_attack_strength(rid, strength)


def active_scan_bases(
    zap: Any,
    base_urls: list[str],
    *,
    max_minutes: int = 30,
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


def collect_zap_supplemental_findings(zap: Any, base_urls: list[str]) -> list[DiagnosisFinding]:
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
            plugin_id = str(alert.get("pluginId", ""))
            if plugin_id not in SUPPLEMENTAL_ALERT_RULE_MAP:
                continue
            severity, rule_id = SUPPLEMENTAL_ALERT_RULE_MAP[plugin_id]
            dedupe = f"{plugin_id}:{alert.get('url')}:{alert.get('param')}"
            if dedupe in seen:
                continue
            seen.add(dedupe)
            findings.append(
                DiagnosisFinding(
                    severity=severity,
                    message=str(alert.get("alert", alert.get("name", "ZAP alert"))),
                    evidence={
                        "rule_id": rule_id,
                        "source": "zap",
                        "engine": "zap",
                        "analysis_mode": "native",
                        "plugin_id": plugin_id,
                        "url": alert.get("url"),
                        "param": alert.get("param"),
                        "risk": alert.get("risk"),
                        "evidence": alert.get("evidence"),
                        "base_url": probe_base_url(base),
                        "trigger": f"zap_rule_{plugin_id}",
                        "trigger_label": PLUGIN_LABELS.get(plugin_id, f"ZAP Rule {plugin_id}"),
                    },
                )
            )
    return findings


def run_zap_phase(
    raw_config: dict[str, Any],
    candidates: list[Any],
    seed_urls: list[str],
    base_urls: list[str],
    auth: dict[str, Any] | None,
    *,
    traversal_payloads: list[str],
    browse_paths: list[str],
    unauth_probe_enabled: bool = True,
    account_auths: list[dict[str, Any]] | None = None,
    idor_probe_enabled: bool = True,
    forced_browse_enabled: bool = True,
    zap_supplemental_enabled: bool = True,
    idor_seeds: dict[str, Any] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """Unified ARGUS probes via ZAP transport + supplemental native scan."""
    zap_cfg = raw_config.get("zap") or {}
    scan_cfg = raw_config.get("diagnosis_2_2") or raw_config.get("scan_2_2") or {}
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped"}

    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)
    runner = _load_runner()
    transport_mod = _load_transport()

    stats: dict[str, Any] = {"zap_proxy": proxy, "mode": "unified+supplemental"}
    unified_findings: list[DiagnosisFinding] = []
    supplemental_findings: list[DiagnosisFinding] = []
    try:
        stats["workspace_reset_before"] = reset_zap_workspace(zap, session_name="argus-g22-start")
        apply_auth_to_zap(zap, auth)

        transport = transport_mod.ZapTransport(zap)
        unified_findings, unified_stats = runner.run_2_2_probes(
            transport,
            engine="zap",
            candidates=candidates,
            base_urls=base_urls,
            traversal_payloads=traversal_payloads,
            browse_paths=browse_paths,
            auth=auth,
            account_auths=account_auths,
            unauth_probe_enabled=unauth_probe_enabled,
            idor_probe_enabled=idor_probe_enabled,
            forced_browse_enabled=forced_browse_enabled,
            idor_seeds=idor_seeds,
            replay_session=None,
        )
        stats["unified"] = unified_stats

        if zap_supplemental_enabled:
            configure_22_supplemental_scanners(zap)
            max_minutes = int(scan_cfg.get("zap_max_minutes", 20))
            scan_ids = active_scan_bases(zap, seed_urls or base_urls, max_minutes=max_minutes)
            supplemental_findings = collect_zap_supplemental_findings(zap, base_urls)
            stats.update(
                {
                    "unified_findings": len(unified_findings),
                    "native_findings": len(supplemental_findings),
                    "active_scans": len(scan_ids),
                    "alerts": len(unified_findings) + len(supplemental_findings),
                }
            )
        else:
            stats.update(
                {
                    "supplemental": "skipped",
                    "unified_findings": len(unified_findings),
                    "native_findings": 0,
                    "active_scans": 0,
                    "alerts": len(unified_findings),
                }
            )
    finally:
        try:
            stats["workspace_reset_after"] = reset_zap_workspace(zap, session_name="argus-g22-done")
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    return unified_findings + supplemental_findings, stats


# Backward-compatible alias for tests importing configure_22_scanners
configure_22_scanners = configure_22_supplemental_scanners
