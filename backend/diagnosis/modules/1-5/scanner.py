"""Orchestrate guideline 1-5 redirect / CORS / crossdomain scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.services.auth_probe_service import login_all_accounts
from app.services.zap_util import ZapNotAvailableError
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent

ProbeMode = Literal["base_only", "sample", "full"]


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g15_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanOptions:
    timeout: float = 8.0
    probe_mode: ProbeMode = "sample"
    sample_size: int = 60
    max_phase_a_jobs: int = 400
    max_phase_b_jobs: int = 800
    max_params_per_endpoint: int = 3
    zap_enabled: bool = False
    zap_max_minutes: int = 10
    zap_seed_cap: int = 200
    cors_enabled: bool = True
    crossdomain_enabled: bool = True


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_1_5") or raw.get("scan_1_5") or {}
    mode = str(cfg.get("probe_mode", "sample")).strip().lower()
    if mode not in ("base_only", "sample", "full"):
        mode = "sample"
    return ScanOptions(
        timeout=float(cfg.get("timeout", 8.0)),
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(10, min(int(cfg.get("sample_size", 60)), 500)),
        max_phase_a_jobs=max(20, min(int(cfg.get("max_phase_a_jobs", 400)), 5000)),
        max_phase_b_jobs=max(20, min(int(cfg.get("max_phase_b_jobs", 800)), 10000)),
        max_params_per_endpoint=max(1, min(int(cfg.get("max_params_per_endpoint", 3)), 10)),
        zap_enabled=bool(cfg.get("zap_enabled", False)),
        zap_max_minutes=max(1, min(int(cfg.get("zap_max_minutes", 10)), 120)),
        zap_seed_cap=max(20, min(int(cfg.get("zap_seed_cap", 200)), 5000)),
        cors_enabled=bool(cfg.get("cors_enabled", True)),
        crossdomain_enabled=bool(cfg.get("crossdomain_enabled", True)),
    )


def _primary_auth(raw: dict[str, Any]) -> dict[str, Any] | None:
    auth_cfg = raw.get("auth") or {}
    accounts = auth_cfg.get("accounts") or []
    if not accounts:
        return None
    logins = login_all_accounts(auth_cfg, accounts)
    return logins[0] if logins else None


def _dedupe_redirect_findings(items: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    seen: set[str] = set()
    out: list[DiagnosisFinding] = []
    for f in items:
        ev = f.evidence or {}
        key = f"{ev.get('rule_id')}|{ev.get('engine')}|{ev.get('test_url') or ev.get('url')}|{ev.get('location')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def run_g15_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)
    targets = _load_local("targets")
    rules = _load_local("redirect_rules")
    probes = _load_local("probes")

    tree = targets.load_api_tree(ctx.data_dir)
    bases = targets.collect_base_urls(raw)
    sink_base = targets.resolve_sink_base(raw)
    run_id = targets.new_run_id()
    cors_origin = targets.resolve_cors_probe_origin(raw, sink_base)

    if not tree and not bases:
        return ScanResult(
            status="skipped",
            message="No api-tree or base URLs — run inventory / Verify first",
            stats={"sink_base": sink_base},
        )

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "probe_mode": opts.probe_mode,
        "sink_base": sink_base,
        "run_id": run_id,
        "cors_probe_origin": cors_origin,
    }

    phase_a = targets.build_phase_a_jobs(
        tree,
        raw_config=raw,
        sink_base=sink_base,
        run_id=run_id,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        max_params_per_endpoint=opts.max_params_per_endpoint,
        max_jobs=opts.max_phase_a_jobs,
    )
    phase_b = targets.build_phase_b_jobs(
        tree,
        raw_config=raw,
        sink_base=sink_base,
        run_id=run_id,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        max_jobs=opts.max_phase_b_jobs,
    )
    redirect_jobs = phase_a + phase_b
    stats["phase_a_jobs"] = len(phase_a)
    stats["phase_b_jobs"] = len(phase_b)

    from diagnosis.progress_reporter import phase, prepare, zap_phase

    cors_targets = targets.build_cors_targets(bases) if opts.cors_enabled and bases else []
    xd_targets = targets.build_crossdomain_targets(bases) if opts.crossdomain_enabled and bases else []
    grand_total = len(redirect_jobs) + len(cors_targets) + len(xd_targets)
    prepare(grand_total, f"1-5: {grand_total} probe(s)")
    progress_offset = 0

    def _seg_progress(segment_total: int, prefix: str):
        def _cb(**kw: Any) -> None:
            nonlocal progress_offset
            local_done = int(kw.get("endpoints_done") or 0)
            done = progress_offset + local_done
            item = str(kw.get("endpoint_id") or "")
            msg = f"{prefix}{done}/{grand_total}"
            if item:
                msg += f" · {item}"
            phase(msg, phase_name="httpx", done=done, total=grand_total)

        return _cb

    if redirect_jobs:
        rf, rstats = probes.run_redirect_jobs(
            redirect_jobs,
            sink_base=sink_base,
            is_open_redirect_fn=rules.is_external_open_redirect,
            timeout=opts.timeout,
            on_progress=_seg_progress(len(redirect_jobs), "redirect "),
        )
        findings.extend(rf)
        stats["redirect"] = rstats
        progress_offset += len(redirect_jobs)

    if opts.cors_enabled and bases:
        cf, cstats = probes.run_cors_probes(
            cors_targets,
            probe_origin=cors_origin,
            analyze_cors_fn=rules.analyze_cors_headers,
            timeout=opts.timeout,
            on_progress=_seg_progress(len(cors_targets), "cors "),
        )
        findings.extend(cf)
        stats["cors"] = cstats
        progress_offset += len(cors_targets)

    if opts.crossdomain_enabled and bases:
        xf, xstats = probes.run_crossdomain_probes(
            xd_targets,
            analyze_crossdomain_fn=rules.analyze_crossdomain_xml,
            timeout=opts.timeout,
            on_progress=_seg_progress(len(xd_targets), "crossdomain "),
        )
        findings.extend(xf)
        stats["crossdomain"] = xstats
        progress_offset += len(xd_targets)

    probe_targets = [
        {"probe_url": j["test_url"], "base_url": j.get("base_url", ""), "label": j["test_url"]}
        for j in redirect_jobs[: opts.zap_seed_cap]
    ]
    for base in bases:
        probe = targets.probe_base_url(base)
        probe_targets.append({"probe_url": probe, "base_url": base, "label": base})

    if opts.zap_enabled:
        zap = _load_local("zap_scan")
        auth = _primary_auth(raw)
        try:
            zap_phase("ZAP 1-5 redirect scan…")
            zf, zstats = zap.run_zap_phase(
                raw,
                probe_targets,
                [targets.probe_base_url(b) for b in bases],
                auth,
                max_minutes=opts.zap_max_minutes,
                seed_cap=opts.zap_seed_cap,
                priority_seed_urls=[j["test_url"] for j in redirect_jobs[:50]],
            )
            findings.extend(zf)
            stats["zap"] = zstats
        except ZapNotAvailableError as exc:
            stats["zap"] = {"error": str(exc)}

    findings = _dedupe_redirect_findings(findings)

    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    stats["findings"] = len(findings)
    stats["by_severity"] = {"high": high, "medium": medium, "low": low, "info": sum(1 for f in findings if f.severity == "info")}

    if high:
        status = "fail"
        message = f"1-5 redirect/CORS: {high} high, {medium} medium finding(s)"
    elif medium:
        status = "warn"
        message = f"1-5 redirect/CORS review: {medium} medium finding(s)"
    else:
        status = "pass"
        message = "1-5 redirect/CORS checks completed — no high/medium issues"

    if opts.probe_mode == "base_only":
        message += " (base_only — redirect sweep skipped)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
