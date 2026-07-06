"""Orchestrate guideline 6-1 error-page information disclosure scan (httpx only)."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from diagnosis.auth_session_pool import DiagnosisAuthPool
from diagnosis.context import DiagnosisContext
from diagnosis.endpoint_auth_passes import (
    build_probe_passes_headers_only,
    load_login_report,
)
from diagnosis.exceptions import DiagnosisCancelled
from diagnosis.probe_transport import HttpxTransport
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent

import sys

if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

ProbeMode = Literal["sample", "full"]


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g61_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanOptions:
    timeout: float = 10.0
    interval_sec: float = 0.02
    probe_mode: ProbeMode = "sample"
    sample_size: int = 40
    max_endpoints: int = 80
    max_requests: int = 8000
    enable_param: bool = True
    enable_body: bool = True
    enable_path: bool = True
    enable_method: bool = True
    enable_header: bool = True
    enable_auth_modes: bool = True
    httpx_enabled: bool = True


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _request_cap(raw_value: Any, default: int) -> int:
    """0 or negative = unlimited; positive = minimum 100."""
    try:
        value = int(raw_value if raw_value is not None else default)
    except (TypeError, ValueError):
        value = default
    if value <= 0:
        return 0
    return max(100, value)


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_6_1") or raw.get("scan_6_1") or {}
    mode = str(cfg.get("probe_mode", "sample")).strip().lower()
    if mode not in ("sample", "full"):
        mode = "sample"
    return ScanOptions(
        timeout=float(cfg.get("timeout", 10.0)),
        interval_sec=max(0.0, min(float(cfg.get("interval_sec", 0.02)), 2.0)),
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(5, min(int(cfg.get("sample_size", 40)), 500)),
        max_endpoints=max(0, int(cfg.get("max_endpoints", 80))),
        max_requests=_request_cap(cfg.get("max_requests"), 8000),
        enable_param=bool(cfg.get("enable_param_fuzz", True)),
        enable_body=bool(cfg.get("enable_body_fuzz", True)),
        enable_path=bool(cfg.get("enable_path_fuzz", True)),
        enable_method=bool(cfg.get("enable_method_fuzz", True)),
        enable_header=bool(cfg.get("enable_header_fuzz", True)),
        enable_auth_modes=bool(cfg.get("enable_auth_modes", True)),
        httpx_enabled=bool(cfg.get("httpx_enabled", True)),
    )


def _overall_status(findings: list[DiagnosisFinding]) -> str:
    if any(f.severity in ("high", "medium") for f in findings):
        return "fail"
    if any(f.severity == "low" for f in findings):
        return "warn"
    return "pass"


def _build_scan_result(
    *,
    all_findings: list[DiagnosisFinding],
    target_meta: dict[str, Any],
    opts: ScanOptions,
    endpoints_done: int,
    budget: Any,
    total_errors: int,
    collapsed_count: int,
    collapse_stats: dict[str, Any],
    enable: dict[str, bool],
    passes: list[tuple[str, dict[str, str]]],
    auth_meta: dict[str, Any],
    payloads: list[Any],
    cancelled: bool = False,
) -> ScanResult:
    by_severity: dict[str, int] = {}
    for f in all_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    stats: dict[str, Any] = {
        **target_meta,
        "probe_mode": opts.probe_mode,
        "payloads": len(payloads),
        "endpoints_probed": endpoints_done,
        "auth_passes": len(passes),
        "auth_passes_scoped": True,
        "sessions": auth_meta.get("sessions", 0),
        "auth_source": auth_meta.get("source"),
        "auth_refresh_count": auth_meta.get("refresh_count", 0),
        "httpx_enabled": opts.httpx_enabled,
        "requests_sent": budget.sent,
        "requests_cap": budget.max_requests if budget.max_requests > 0 else None,
        "requests_unlimited": budget.unlimited,
        "budget_exhausted": budget.exhausted(),
        "requests_by_family": budget.by_family,
        "http_errors": total_errors,
        "httpx_leaks": collapsed_count,
        "leaks": len(all_findings),
        "by_severity": by_severity,
        **collapse_stats,
        "triggers_enabled": enable,
    }
    if cancelled:
        stats["cancelled"] = True

    if cancelled:
        status = "cancelled"
        message = f"Cancelled after {endpoints_done} endpoint(s)"
    else:
        status = _overall_status(all_findings)
        message = f"Probed {endpoints_done} endpoint(s)"

    if opts.httpx_enabled:
        message += f", {budget.sent} httpx request(s), {collapsed_count} leak(s)"
    if cancelled:
        message += f" — {len(all_findings)} finding(s) collected before stop"
    return ScanResult(findings=all_findings, stats=stats, status=status, message=message)


def run_g61_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    from app.services import diagnosis_progress as dp

    _ = module_dir
    opts = _scan_options(ctx.raw_config)
    cfg = ctx.raw_config.get("diagnosis_6_1") or {}

    targets_mod = _load_local("targets")
    probes_mod = _load_local("probes")

    endpoints, target_meta = targets_mod.build_endpoint_targets(
        ctx.raw_config,
        data_dir=ctx.data_dir,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        max_endpoints=opts.max_endpoints,
    )
    if not endpoints:
        reason = target_meta.get("message") or "no_targets"
        return ScanResult(
            status="skipped",
            message=(
                "No API endpoints to probe — configure dashboard Base URLs and run Verify "
                "to build api-tree-verified.json"
            ),
            stats={"reason": reason, **target_meta},
        )

    total_eps = len(endpoints)
    dp.update(
        phase="preparing",
        message=f"6-1: {total_eps} API 대상 · 인증 패스 준비",
        endpoints_total=total_eps,
    )

    payloads = probes_mod.build_payloads_from_config(cfg)
    enable = {
        "param": opts.enable_param,
        "body": opts.enable_body,
        "path": opts.enable_path,
        "method": opts.enable_method,
        "header": opts.enable_header,
    }

    auth_pool = DiagnosisAuthPool(ctx.raw_config, data_dir=ctx.data_dir)
    login_report = load_login_report(ctx.data_dir, ctx.raw_config)

    def _snapshot_auth_meta() -> dict[str, Any]:
        return {**auth_pool.meta, "refresh_count": auth_pool.refresh_count}

    def _passes_for_ep(ep, sessions: list[dict[str, Any]]) -> list[tuple[str, dict[str, str]]]:
        return build_probe_passes_headers_only(
            ep,
            sessions,
            login_report=login_report,
            enable_auth_modes=opts.enable_auth_modes,
        )

    sample_passes = _passes_for_ep(endpoints[0], auth_pool.sessions()) if endpoints else []

    raw_findings: list[DiagnosisFinding] = []
    total_errors = 0
    endpoints_done = 0
    budget = probes_mod.RequestBudget(max_requests=opts.max_requests)

    def _probe_progress(
        *,
        endpoints_done: int,
        endpoints_total: int,
        requests_sent: int,
        requests_cap: int | None,
        endpoint_id: str,
        engine: str,
    ) -> None:
        cap_note = f" / {requests_cap:,}" if requests_cap else ""
        dp.update(
            phase=f"{engine}_fuzz",
            message=(
                f"[{engine}] API {endpoints_done}/{endpoints_total} · "
                f"요청 {requests_sent:,}{cap_note} · {endpoint_id[:80]}"
            ),
            endpoints_done=endpoints_done,
            endpoints_total=endpoints_total,
            requests_sent=requests_sent,
            requests_cap=requests_cap,
        )

    collapsed: list[DiagnosisFinding] = []
    collapse_stats: dict[str, Any] = {}
    all_findings: list[DiagnosisFinding] = []

    try:
        if not opts.httpx_enabled:
            return ScanResult(
                status="skipped",
                message="httpx disabled — nothing to run",
                stats={"reason": "httpx_enabled=false", **target_meta},
            )

        dp.update(phase="httpx", message=f"httpx — {total_eps} API")
        with HttpxTransport(timeout=opts.timeout) as transport:
            raw_findings, total_errors, endpoints_done = probes_mod.run_endpoints_probes(
                endpoints,
                transport=transport,
                engine="httpx",
                payloads=payloads,
                timeout=opts.timeout,
                interval_sec=opts.interval_sec,
                budget=budget,
                passes=sample_passes,
                enable=enable,
                on_progress=_probe_progress,
                auth_pool=auth_pool,
                build_passes=_passes_for_ep,
            )

        collapsed, collapse_stats = probes_mod.collapse_auth_findings(raw_findings)
        all_findings = list(collapsed)
    except DiagnosisCancelled:
        if not collapsed and raw_findings:
            collapsed, collapse_stats = probes_mod.collapse_auth_findings(raw_findings)
        all_findings = list(collapsed)
        return _build_scan_result(
            all_findings=all_findings,
            target_meta=target_meta,
            opts=opts,
            endpoints_done=endpoints_done,
            budget=budget,
            total_errors=total_errors,
            collapsed_count=len(collapsed),
            collapse_stats=collapse_stats,
            enable=enable,
            passes=sample_passes,
            auth_meta=_snapshot_auth_meta(),
            payloads=payloads,
            cancelled=True,
        )

    return _build_scan_result(
        all_findings=all_findings,
        target_meta=target_meta,
        opts=opts,
        endpoints_done=endpoints_done,
        budget=budget,
        total_errors=total_errors,
        collapsed_count=len(collapsed),
        collapse_stats=collapse_stats,
        enable=enable,
        passes=sample_passes,
        auth_meta=_snapshot_auth_meta(),
        payloads=payloads,
        cancelled=False,
    )
