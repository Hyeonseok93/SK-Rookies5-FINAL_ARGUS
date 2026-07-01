"""Orchestrate guideline 5-2 sensitive data in request/response scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from diagnosis.context import DiagnosisContext
from diagnosis.probe_auth import all_account_auths_with_meta, probe_request_headers, session_auth_mode
from diagnosis.probe_transport import HttpxTransport
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent

ProbeMode = Literal["sample", "full"]


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g52_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    if str(_MODULE_DIR) not in sys.path:
        sys.path.insert(0, str(_MODULE_DIR))
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanOptions:
    timeout: float = 12.0
    interval_sec: float = 0.02
    probe_mode: ProbeMode = "sample"
    sample_size: int = 40
    max_endpoints: int = 80
    check_request_url: bool = True
    check_request_body: bool = True
    check_response_body: bool = True
    check_http_plain: bool = True
    enable_auth_modes: bool = True


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_5_2") or raw.get("scan_5_2") or {}
    mode = str(cfg.get("probe_mode", "sample")).strip().lower()
    if mode not in ("sample", "full"):
        mode = "sample"
    return ScanOptions(
        timeout=float(cfg.get("timeout", 12.0)),
        interval_sec=max(0.0, min(float(cfg.get("interval_sec", 0.02)), 2.0)),
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(5, min(int(cfg.get("sample_size", 40)), 500)),
        max_endpoints=max(0, int(cfg.get("max_endpoints", 80))),
        check_request_url=bool(cfg.get("check_request_url", True)),
        check_request_body=bool(cfg.get("check_request_body", True)),
        check_response_body=bool(cfg.get("check_response_body", True)),
        check_http_plain=bool(cfg.get("check_http_plain", True)),
        enable_auth_modes=bool(cfg.get("enable_auth_modes", True)),
    )


def _overall_status(findings: list[DiagnosisFinding]) -> str:
    if any(f.severity in ("high", "medium") for f in findings):
        return "fail"
    if any(f.severity == "low" for f in findings):
        return "warn"
    return "pass"


def _build_passes(
    auth_sessions: list[dict[str, Any]],
    *,
    enable_auth_modes: bool,
) -> list[tuple[str, dict[str, str], dict[str, Any] | None]]:
    passes: list[tuple[str, dict[str, str], dict[str, Any] | None]] = [("anonymous", {}, None)]
    if enable_auth_modes:
        for session in auth_sessions:
            passes.append(
                (session_auth_mode(session), probe_request_headers(session), session)
            )
    return passes


def run_g52_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    from app.services import diagnosis_progress as dp

    _ = module_dir
    opts = _scan_options(ctx.raw_config)

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
        message=f"5-2: {total_eps} API · 요청/응답 PII 검사",
        endpoints_total=total_eps,
    )

    auth_sessions, auth_meta = all_account_auths_with_meta(ctx.raw_config, data_dir=ctx.data_dir)
    passes = _build_passes(auth_sessions, enable_auth_modes=opts.enable_auth_modes)

    def _on_progress(**kw: Any) -> None:
        done = int(kw.get("endpoints_done") or 0)
        total = int(kw.get("endpoints_total") or total_eps)
        eid = str(kw.get("endpoint_id") or "")
        dp.update(
            phase="httpx_pii",
            message=f"[5-2] API {done}/{total} · {eid[:80]}",
            endpoints_done=done,
            endpoints_total=total,
            requests_sent=done * len(passes),
        )

    raw_findings: list[DiagnosisFinding] = []
    errors = 0
    endpoints_done = 0

    dp.update(phase="httpx", message=f"httpx — {total_eps} API × {len(passes)} auth pass(es)")
    with HttpxTransport(timeout=opts.timeout) as transport:
        raw_findings, errors, endpoints_done, coverage = probes_mod.run_endpoints(
            endpoints,
            transport=transport,
            timeout=opts.timeout,
            interval_sec=opts.interval_sec,
            passes=passes,
            check_request_url=opts.check_request_url,
            check_request_body=opts.check_request_body,
            check_response_body=opts.check_response_body,
            check_http_plain=opts.check_http_plain,
            on_progress=_on_progress,
        )

    collapsed, collapse_stats = probes_mod.collapse_findings(raw_findings)

    by_category: dict[str, int] = {}
    by_direction: dict[str, int] = {}
    for f in collapsed:
        ev = f.evidence or {}
        cat = str(ev.get("category") or "unknown")
        direction = str(ev.get("direction") or "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        by_direction[direction] = by_direction.get(direction, 0) + 1

    stats: dict[str, Any] = {
        **target_meta,
        "probe_mode": opts.probe_mode,
        "endpoints_probed": endpoints_done,
        "auth_passes": len(passes),
        "sessions": auth_meta.get("sessions", 0),
        "http_errors": errors,
        "issues": len(collapsed),
        "coverage": coverage,
        "by_category": by_category,
        "by_direction": by_direction,
        **collapse_stats,
        "checks": {
            "request_url": opts.check_request_url,
            "request_body": opts.check_request_body,
            "response_body": opts.check_response_body,
            "http_plain": opts.check_http_plain,
        },
    }

    status = _overall_status(collapsed)
    cov = coverage
    requests_total = int(cov.get("requests") or 0)
    with_body = int(cov.get("responses_with_body") or 0)
    ok_2xx = int(cov.get("status_2xx") or 0)
    auth_401 = int(cov.get("status_401") or 0)
    emails_seen = int(cov.get("emails_seen") or 0)
    phones_seen = int(cov.get("phones_seen") or 0)

    if len(collapsed) == 0:
        conn_err = int(cov.get("connection_errors") or 0)
        if requests_total == 0:
            detail = "no HTTP responses captured"
        elif conn_err >= requests_total:
            detail = (
                f"all {conn_err} request(s) unreachable — "
                "check API is up and ARGUS_PROBE_HOST (Docker: host.docker.internal)"
            )
        elif with_body == 0:
            detail = "responses returned empty bodies"
        elif ok_2xx == 0 and auth_401 > 0:
            detail = f"mostly 401 ({auth_401}/{requests_total}) — check test accounts / Verify"
        elif emails_seen == 0 and phones_seen == 0:
            detail = f"{with_body} bodies scanned, no sensitive fields in JSON"
        else:
            detail = (
                f"{with_body} bodies scanned, sensitive fields seen "
                f"(email {emails_seen}, phone {phones_seen}) but masked or absent"
            )
        message = (
            f"Probed {endpoints_done} endpoint(s) x {len(passes)} auth pass(es) - "
            f"0 unmasked PII ({detail})"
        )
    else:
        by_cat = ", ".join(f"{k} {v}" for k, v in sorted(by_category.items()))
        message = (
            f"Probed {endpoints_done} endpoint(s) x {len(passes)} auth pass(es) - "
            f"{len(collapsed)} unmasked PII hit(s)"
            + (f" ({by_cat})" if by_cat else "")
            + f" · {with_body} bodies / {ok_2xx} OK"
        )
    return ScanResult(findings=collapsed, stats=stats, status=status, message=message)
