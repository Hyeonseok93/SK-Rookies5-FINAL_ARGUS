"""ZAP unified param fuzz (ZapTransport) + supplemental rules 90022/10023."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from app.services.zap_util import (
    apply_auth_to_zap,
    connect_zap,
    ensure_zap_proxy,
    probe_url,
    reset_zap_workspace,
    seed_probe_urls,
    select_seed_urls,
    stop_zap_scans,
)
from diagnosis.exceptions import DiagnosisCancelled
from diagnosis.probe_transport import ZapTransport
from diagnosis.result import DiagnosisFinding
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint

ACTIVE_SCANNER_RULES: tuple[tuple[int, str, str], ...] = (
    (90022, "Medium", "High"),
)

ERROR_DISCLOSURE_PLUGIN_IDS: frozenset[str] = frozenset({"90022", "10023"})

PLUGIN_LABELS: dict[str, str] = {
    "90022": "ZAP Rule 90022 (Application Error Disclosure)",
    "10023": "ZAP Rule 10023 (Debug Error Messages)",
}

PLUGIN_SEVERITY: dict[str, str] = {
    "90022": "medium",
    "10023": "medium",
}


def is_61_error_plugin(plugin_id: str) -> bool:
    pid = str(plugin_id or "").strip()
    return pid in ERROR_DISCLOSURE_PLUGIN_IDS


def configure_61_supplemental_scanners(zap: Any) -> None:
    zap.ascan.disable_all_scanners()
    for rule_id, threshold, strength in ACTIVE_SCANNER_RULES:
        rid = str(rule_id)
        zap.ascan.enable_scanners(rid)
        zap.ascan.set_scanner_alert_threshold(rid, threshold)
        zap.ascan.set_scanner_attack_strength(rid, strength)


def endpoints_to_probe_targets(endpoints: list[Endpoint]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    for ep in endpoints:
        probe = build_probe_request(ep)
        targets.append({"method": str(probe["method"]), "url": str(probe["url"])})
    return targets


def _raise_if_cancelled() -> None:
    from app.services import diagnosis_progress as dp

    if dp.is_cancel_requested():
        raise DiagnosisCancelled("User cancelled diagnosis")


def _wait_for_passive_scan_cancellable(zap: Any, *, max_seconds: int = 90) -> int:
    deadline = time.time() + max_seconds
    last_remaining = 0
    while time.time() < deadline:
        _raise_if_cancelled()
        try:
            last_remaining = int(zap.pscan.records_to_scan)
        except Exception:
            break
        if last_remaining <= 0:
            break
        time.sleep(1)
    return last_remaining


def active_scan_bases(
    zap: Any,
    base_urls: list[str],
    *,
    max_minutes: int = 15,
) -> list[str]:
    scan_ids: list[str] = []
    for base in base_urls:
        _raise_if_cancelled()
        try:
            sid = zap.ascan.scan(url=probe_url(base.rstrip("/")), recurse=False, scanpolicyname="")
            if sid:
                scan_ids.append(str(sid))
        except Exception:
            continue

    deadline = time.time() + max_minutes * 60
    while time.time() < deadline:
        _raise_if_cancelled()
        pending = 0
        for sid in scan_ids:
            try:
                if int(zap.ascan.status(sid)) < 100:
                    pending += 1
            except Exception:
                continue
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


def zap_alert_to_finding(alert: dict[str, Any], *, base_url: str) -> DiagnosisFinding | None:
    plugin_id = str(alert.get("pluginId", ""))
    if not is_61_error_plugin(plugin_id):
        return None
    severity = _severity_from_alert(plugin_id, str(alert.get("risk", "Low")))
    url = str(alert.get("url") or "")
    name = str(alert.get("alert") or alert.get("name") or PLUGIN_LABELS.get(plugin_id, "ZAP error disclosure"))
    other = str(alert.get("other") or alert.get("evidence") or "").strip()
    return DiagnosisFinding(
        severity=severity,
        message=f"[6-1][zap-native][{plugin_id}] {name} at `{url}`",
        evidence={
            "rule_id": f"6-1-zap-{plugin_id}",
            "source": "zap",
            "engine": "zap-native",
            "category": "zap_error_disclosure",
            "plugin_id": plugin_id,
            "url": url,
            "base_url": base_url,
            "param": alert.get("param"),
            "risk": alert.get("risk"),
            "other_info": other or None,
            "trigger": f"zap_rule_{plugin_id}",
            "trigger_label": PLUGIN_LABELS.get(plugin_id, f"ZAP Rule {plugin_id}"),
            "remediation": "Return generic error responses without stack traces, SQL text, or debug details.",
        },
    )


def collect_zap_native_findings(zap: Any, base_urls: list[str]) -> list[DiagnosisFinding]:
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
    endpoints: list[Endpoint],
    base_urls: list[str],
    auth: dict[str, Any] | None,
    probes_mod: Any,
    *,
    payloads: list[Any],
    passes: list[tuple[str, dict[str, str]]],
    timeout: float,
    interval_sec: float,
    max_requests: int,
    enable: dict[str, bool],
    max_minutes: int = 15,
    seed_cap: int = 200,
    priority_seed_urls: list[str] | None = None,
    zap_unified_enabled: bool = True,
    zap_supplemental_enabled: bool = True,
    on_progress: Callable[..., None] | None = None,
    auth_pool: Any | None = None,
    build_passes: Callable[[Endpoint, list[dict[str, Any]]], list[tuple[str, dict[str, str]]]]
    | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    ZAP phase — unified ARGUS param/body/path fuzz via ZapTransport (2-2 pattern),
    then optional native active 90022 + passive 10023.
    """
    scan_cfg = raw_config.get("diagnosis_6_1") or raw_config.get("scan_6_1") or {}
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped", "reason": "zap_enabled=false"}

    zap_cfg = raw_config.get("zap") or {}
    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)

    stats: dict[str, Any] = {
        "zap_proxy": proxy,
        "mode": "unified+supplemental",
        "plugin_ids": sorted(ERROR_DISCLOSURE_PLUGIN_IDS),
    }
    unified_findings: list[DiagnosisFinding] = []
    native_findings: list[DiagnosisFinding] = []
    unified_requests_sent = 0

    try:
        stats["workspace_reset_before"] = reset_zap_workspace(zap, session_name="argus-g61-start")
        apply_auth_to_zap(zap, auth)

        if zap_unified_enabled and endpoints:
            transport = ZapTransport(zap)
            budget = probes_mod.RequestBudget(max_requests=max_requests)
            raw_unified, unified_errors, endpoints_done = probes_mod.run_endpoints_probes(
                endpoints,
                transport=transport,
                engine="zap",
                payloads=payloads,
                timeout=timeout,
                interval_sec=interval_sec,
                budget=budget,
                passes=passes,
                enable=enable,
                on_progress=on_progress,
                auth_pool=auth_pool,
                build_passes=build_passes,
            )
            unified_collapsed, unified_collapse_stats = probes_mod.collapse_auth_findings(raw_unified)
            unified_findings = unified_collapsed
            stats["unified"] = {
                "requests_sent": budget.sent,
                "requests_cap": budget.max_requests if budget.max_requests > 0 else None,
                "requests_unlimited": budget.unlimited,
                "budget_exhausted": budget.exhausted(),
                "requests_by_family": budget.by_family,
                "endpoints_probed": endpoints_done,
                "http_errors": unified_errors,
                "findings": len(unified_findings),
                **unified_collapse_stats,
            }
            unified_requests_sent = budget.sent
            _wait_for_passive_scan_cancellable(zap, max_seconds=90)

        if zap_supplemental_enabled:
            _raise_if_cancelled()
            if on_progress:
                on_progress(
                    endpoints_done=len(endpoints),
                    endpoints_total=len(endpoints),
                    requests_sent=unified_requests_sent,
                    requests_cap=max_requests if max_requests > 0 else None,
                    endpoint_id="zap-supplemental",
                    engine="zap",
                )
            configure_61_supplemental_scanners(zap)
            probe_targets = endpoints_to_probe_targets(endpoints)
            seed_urls = select_seed_urls(
                probe_targets,
                seed_cap,
                priority_urls=priority_seed_urls,
            )
            seeded = seed_probe_urls(zap, seed_urls)
            passive_remaining = _wait_for_passive_scan_cancellable(zap)
            scan_ids = active_scan_bases(zap, base_urls, max_minutes=max_minutes)
            native_findings = collect_zap_native_findings(zap, base_urls)
            stats["supplemental"] = {
                "seeded": seeded,
                "seed_cap": seed_cap,
                "seed_candidates": len(seed_urls),
                "priority_seeded": len(priority_seed_urls or []),
                "passive_remaining": passive_remaining,
                "active_scans": len(scan_ids),
                "findings": len(native_findings),
            }

        findings = unified_findings + native_findings
        stats["unified_findings"] = len(unified_findings)
        stats["native_findings"] = len(native_findings)
        stats["alerts"] = len(findings)
        stats["findings"] = len(findings)
    except DiagnosisCancelled:
        stop_zap_scans(zap)
        stats["cancelled"] = True
        findings = unified_findings + native_findings
        stats["unified_findings"] = len(unified_findings)
        stats["native_findings"] = len(native_findings)
        stats["alerts"] = len(findings)
        stats["findings"] = len(findings)
    finally:
        try:
            stats["workspace_reset_after"] = reset_zap_workspace(zap, session_name="argus-g61-done")
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    findings = unified_findings + native_findings
    stats["unified_findings"] = len(unified_findings)
    stats["native_findings"] = len(native_findings)
    stats["alerts"] = len(findings)
    stats["findings"] = len(findings)
    return findings, stats


configure_61_scanners = configure_61_supplemental_scanners
collect_zap_error_findings = collect_zap_native_findings
