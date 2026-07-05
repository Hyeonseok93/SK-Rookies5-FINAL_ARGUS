"""Orchestrate guideline 1-2 injection scan (ZAP → injector verify → api-tree direct)."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.zap_util import ZapNotAvailableError
from diagnosis.context import DiagnosisContext
from diagnosis.probe_auth import primary_account_auth, probe_request_headers
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g12_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _bootstrap_locals():
    models = _load_local("models")
    sys.modules["models"] = models
    sample_values = _load_local("sample_values")
    sys.modules["sample_values"] = sample_values
    targets = _load_local("targets")
    payload_injector = _load_local("payload_injector")
    injector_runner = _load_local("injector_runner")
    sys.modules["zap_engine"] = _load_local("zap_engine")
    zap_scan = _load_local("zap_scan")
    return models, targets, payload_injector, injector_runner, zap_scan


@dataclass
class ScanOptions:
    injector_enabled: bool = True
    direct_enabled: bool = True
    zap_enabled: bool = False
    zap_max_minutes: int = 20
    verification_mode: str = "balanced"
    injection_types: list[str] = field(default_factory=lambda: ["SQL", "NOSQL", "COMMAND", "XPATH"])
    include_unsafe_methods: bool = False
    keep_all_results: bool = False


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_1_2") or raw.get("scan_1_2") or {}
    types_raw = cfg.get("injection_types")
    types: list[str] = []
    if isinstance(types_raw, list):
        types = [str(t) for t in types_raw if str(t).strip()]
    elif isinstance(types_raw, str) and types_raw.strip():
        types = [t.strip() for t in types_raw.split(",") if t.strip()]
    injector_on = bool(cfg.get("injector_enabled", True))
    return ScanOptions(
        injector_enabled=injector_on,
        direct_enabled=bool(cfg.get("direct_enabled", injector_on)),
        zap_enabled=bool(cfg.get("zap_enabled", False)),
        zap_max_minutes=max(1, min(int(cfg.get("zap_max_minutes", 20)), 120)),
        verification_mode=str(cfg.get("verification_mode", "balanced")),
        injection_types=types or ["SQL", "NOSQL", "COMMAND", "XPATH"],
        include_unsafe_methods=bool(cfg.get("include_unsafe_methods", False)),
        keep_all_results=bool(cfg.get("keep_all_results", False)),
    )


def _resolve_injection_auth(auth: dict[str, Any] | None) -> tuple[str, dict[str, str]]:
    """Cookie-auth APIs need Cookie header; Bearer jwt breaks Onde-style targets."""
    if not auth:
        return "", {}
    session_headers = probe_request_headers(auth)
    delivery = str(auth.get("delivery") or "").lower()
    if delivery == "cookie" or "Cookie" in session_headers:
        return "", session_headers
    jwt_token = _jwt_from_auth(auth)
    return jwt_token, session_headers


def _jwt_from_auth(auth: dict[str, Any] | None) -> str:
    if not auth:
        return ""
    for key in ("authorization", "Authorization", "access_token", "accessToken", "token"):
        val = auth.get(key)
        if val:
            return str(val)
    headers = auth.get("headers") or {}
    if isinstance(headers, dict):
        for key in ("Authorization", "authorization"):
            val = headers.get(key)
            if val:
                return str(val)
    return ""


def _result_to_finding(result: Any, models_mod: Any, runner_mod: Any, *, engine: str) -> DiagnosisFinding:
    status = result.verification_status
    status_val = status.value if isinstance(status, models_mod.VerificationStatus) else str(status)
    injection = result.injection_type
    injection_val = injection.value if hasattr(injection, "value") else str(injection)
    severity = runner_mod.severity_for_result(result)
    message = (
        f"[{injection_val}] {result.method} {result.url} — param `{result.param}` "
        f"({status_val}, {result.classification or 'unclassified'})"
    )
    return DiagnosisFinding(
        severity=severity,
        message=message,
        evidence={
            "engine": engine,
            "target_source": "api_tree",
            "rule_id": "G12_INJECTION",
            "injection_type": injection_val,
            "verification_status": status_val,
            "classification": result.classification,
            "confidence": result.confidence,
            "argus_risk": result.argus_risk,
            "has_zap": result.has_zap,
            "method": result.method,
            "url": result.url,
            "param": result.param,
            "plugin_id": result.plugin_id,
            "plugin_name": result.plugin_name,
            "verification_reason": result.verification_reason,
            "verification_methods": result.verification_methods,
            "custom_payload": result.custom_payload,
            "detail": result.to_dict(),
        },
    )


def run_g12_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    models_mod, targets_mod, payload_injector_mod, runner_mod, zap_scan_mod = _bootstrap_locals()
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)

    targets, target_meta = targets_mod.load_scan_targets(
        ctx.data_dir,
        raw,
    )

    if target_meta.get("error") == "no_api_tree":
        return ScanResult(
            status="error",
            message="api-tree 없음 — Build 후 Verify를 실행하세요 (data/api-tree-verified.json)",
            stats=target_meta,
        )
    if target_meta.get("error") == "no_matching_base_urls":
        return ScanResult(
            status="skipped",
            message="api-tree endpoint가 dashboard Base URL과 일치하지 않습니다",
            stats=target_meta,
        )
    if not targets and not opts.zap_enabled:
        return ScanResult(
            status="skipped",
            message="스캔할 대상 endpoint가 없습니다",
            stats=target_meta,
        )

    auth = primary_account_auth(raw, data_dir=ctx.data_dir)
    jwt_token, session_headers = _resolve_injection_auth(auth)
    injection_types = runner_mod.parse_injection_types(opts.injection_types)

    from diagnosis.progress_reporter import prepare, step_progress, zap_phase

    prepare(max(len(targets), 1), "1-2 injection scan")
    all_detection_results: list[Any] = []
    stats: dict[str, Any] = {**target_meta}

    # Phase 1–2: ZAP → injector verify (branch default pipeline)
    if opts.zap_enabled:
        zap_phase("1-2 ZAP injection scan…")
        try:
            zap_raw, zap_stats = zap_scan_mod.run_zap_injection_phase(
                raw,
                ctx.data_dir,
                jwt_token=jwt_token,
                session_headers=session_headers,
                max_minutes=opts.zap_max_minutes,
            )
            stats["zap"] = zap_stats
            if zap_stats.get("error"):
                stats["zap_error"] = zap_stats["error"]
            elif opts.injector_enabled and zap_raw:
                zap_progress = step_progress(total=len(zap_raw), phase_name="zap_verify", label="ZAP verify")
                verified, vstats = runner_mod.verify_zap_alerts(
                    zap_raw,
                    jwt_token=jwt_token,
                    injectors_mod=payload_injector_mod,
                    verification_mode=opts.verification_mode,
                    session_headers=session_headers,
                    progress_cb=lambda d, t, lbl: zap_progress(d, lbl),
                )
                all_detection_results.extend(verified)
                stats["zap_verify"] = vstats
            elif zap_raw:
                all_detection_results.extend(zap_raw)
        except ZapNotAvailableError as exc:
            stats["zap"] = {"error": str(exc)}

    # Phase 3: Direct injector on api-tree targets (branch --direct, api-tree adapted)
    if opts.injector_enabled and opts.direct_enabled and targets:
        total_probes = sum(
            len([p for p in t.params if p.location.value in {"query", "path", "body", "header"}])
            for t in targets
            if opts.include_unsafe_methods or t.method.upper() not in {"DELETE", "PATCH"}
        ) * len(injection_types)
        direct_progress = step_progress(total=max(total_probes, 1), phase_name="injector", label="1-2 direct")

        def _progress(probe: int, total: int, label: str) -> None:
            direct_progress(min(probe, max(total, 1)), label[:120])

        direct_results, direct_stats = runner_mod.run_direct_verification(
            targets,
            jwt_token=jwt_token,
            injectors_mod=payload_injector_mod,
            injection_types=injection_types,
            verification_mode=opts.verification_mode,
            include_unsafe=opts.include_unsafe_methods,
            keep_all=opts.keep_all_results,
            session_headers=session_headers,
            progress_cb=_progress,
        )
        all_detection_results.extend(direct_results)
        stats["direct"] = direct_stats

    if not all_detection_results and not opts.zap_enabled and not opts.direct_enabled:
        return ScanResult(
            status="skipped",
            message="ZAP와 injector가 모두 비활성화되어 있습니다",
            stats=stats,
        )

    merged = runner_mod.dedupe_results(all_detection_results)
    annotated = [runner_mod.annotate_result(r) for r in merged]

    findings: list[DiagnosisFinding] = []
    for result in annotated:
        engine = "zap+requests" if result.has_zap else "requests"
        status_val = (
            result.verification_status.value
            if isinstance(result.verification_status, models_mod.VerificationStatus)
            else str(result.verification_status)
        )
        if opts.keep_all_results or status_val in {
            models_mod.VerificationStatus.VERIFIED.value,
            models_mod.VerificationStatus.SUSPECTED.value,
            models_mod.VerificationStatus.ERROR.value,
        }:
            if runner_mod.should_report_injection_finding(result):
                findings.append(_result_to_finding(result, models_mod, runner_mod, engine=engine))

    verified = sum(
        1
        for f in findings
        if (f.evidence or {}).get("verification_status") == models_mod.VerificationStatus.VERIFIED.value
    )
    confirmed = sum(
        1
        for f in findings
        if (f.evidence or {}).get("classification") in runner_mod.HIGH_CONFIDENCE_CLASSIFICATIONS
    )
    suspected = sum(
        1
        for f in findings
        if (f.evidence or {}).get("verification_status") == models_mod.VerificationStatus.SUSPECTED.value
    )

    stats.update(
        {
            "verified_findings": verified,
            "confirmed_findings": confirmed,
            "suspected_findings": suspected,
            "excluded_server_error_signals": sum(
                1
                for r in annotated
                if (r.classification or "") in runner_mod.EXCLUDED_FROM_INJECTION_REPORT
            ),
            "auth_present": bool(jwt_token or session_headers),
            "results_total": len(annotated),
            "findings_reported": len(findings),
        }
    )

    if confirmed > 0:
        status = "fail"
        weak = max(0, verified - confirmed)
        message = f"Injection 확정 {confirmed}건 (의심 {suspected}건)"
        if weak:
            message += f", boolean 등 약한 정탐 {weak}건"
    elif verified > 0:
        status = "warn"
        message = f"Injection 약한 정탐 {verified}건 (boolean 등) — strict/time 재검증 권장 (의심 {suspected}건)"
    elif suspected > 0:
        status = "warn"
        message = f"Injection 의심 {suspected}건 — 수동 재검증 권장"
    else:
        status = "pass"
        message = f"재현 가능한 Injection 없음 (api-tree {len(targets)} targets)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
