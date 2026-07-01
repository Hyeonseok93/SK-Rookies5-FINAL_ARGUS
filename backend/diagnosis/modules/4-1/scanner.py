"""Orchestrate guideline 4-1 cookie / storage scan (phase A)."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent

ProbeMode = Literal["base_only", "sample", "full"]


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g41_{name}"
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
    sample_size: int = 40
    max_endpoints: int = 80
    max_pairs_per_endpoint: int = 12
    cross_cookie_enabled: bool = True
    tamper_enabled: bool = True
    tamper_max_endpoints: int = 30
    cookie_attr_enabled: bool = True
    cookie_attr_strict: bool = True
    auth_required_only: bool = True
    auth_profiles: list[str] = field(default_factory=lambda: list(
        ["bearer", "cookie_access", "cookie_refresh", "dual", "browser_full"]
    ))
    partial_cross_tamper: bool = True
    max_tamper_variants_per_session: int = 24


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_4_1") or raw.get("scan_4_1") or {}
    mode = str(cfg.get("probe_mode", "sample")).strip().lower()
    if mode not in ("base_only", "sample", "full"):
        mode = "sample"
    from inventory.auth_surfaces import resolve_auth_profiles

    return ScanOptions(
        timeout=float(cfg.get("timeout", 8.0)),
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(5, min(int(cfg.get("sample_size", 40)), 500)),
        max_endpoints=max(10, min(int(cfg.get("max_endpoints", 80)), 500)),
        max_pairs_per_endpoint=max(2, min(int(cfg.get("max_pairs_per_endpoint", 12)), 50)),
        cross_cookie_enabled=bool(cfg.get("cross_cookie_enabled", True)),
        tamper_enabled=bool(cfg.get("tamper_enabled", True)),
        tamper_max_endpoints=max(5, min(int(cfg.get("tamper_max_endpoints", 30)), 200)),
        cookie_attr_enabled=bool(cfg.get("cookie_attr_enabled", True)),
        cookie_attr_strict=bool(cfg.get("cookie_attr_strict", True)),
        auth_required_only=bool(cfg.get("auth_required_only", True)),
        auth_profiles=resolve_auth_profiles(cfg.get("auth_profiles")),
        partial_cross_tamper=bool(cfg.get("partial_cross_tamper", True)),
        max_tamper_variants_per_session=max(
            4, min(int(cfg.get("max_tamper_variants_per_session", 24)), 80)
        ),
    )


def _dedupe_findings(items: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    seen: set[str] = set()
    out: list[DiagnosisFinding] = []
    for f in items:
        ev = f.evidence or {}
        key = (
            f"{ev.get('rule_id')}|{ev.get('endpoint_id')}|{ev.get('other_email')}|"
            f"{ev.get('other_login_url')}|{ev.get('trigger')}|{ev.get('auth_profile')}|"
            f"{ev.get('cookie_name')}|{ev.get('login_url')}"
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def run_g41_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)
    targets = _load_local("targets")
    rules = _load_local("cookie_rules")
    probes = _load_local("probes")
    cookie_attr = _load_local("cookie_attr_probes")

    tree = targets.load_api_tree(ctx.data_dir)
    login_report = targets.load_login_report(ctx.data_dir, raw)
    auth_cfg = raw.get("auth") or {}
    from app.services.test_accounts_service import load_test_accounts

    test_accounts = load_test_accounts().get("accounts") or []
    sessions: list[dict[str, Any]] = []
    auth_meta: dict[str, Any] = {"source": "skipped_base_only", "sessions": 0}
    if opts.probe_mode != "base_only":
        sessions, auth_meta = targets.load_sessions(raw, ctx.data_dir)

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "probe_mode": opts.probe_mode,
        "sessions": len(sessions),
        "session_emails": sorted({str(s.get("email") or "") for s in sessions if s.get("email")}),
        "auth_source": auth_meta.get("source"),
        "auth_profiles": opts.auth_profiles,
    }

    matrix = rules.login_relationship_info(login_report)
    if matrix:
        findings.append(matrix)
        stats["login_matrix"] = {
            "accounts": len(login_report.get("accounts") or []) if login_report else 0,
            "login_entries": len(login_report.get("login_entries") or []) if login_report else 0,
        }

    if opts.cookie_attr_enabled and login_report:
        from diagnosis.progress_reporter import phase

        phase("4-1: cookie attribute probes…", phase_name="httpx", done=0, total=1)
        caf, castats = cookie_attr.run_cookie_attribute_probes(
            auth_cfg,
            test_accounts,
            login_report,
            data_dir=ctx.data_dir,
            strict=opts.cookie_attr_strict,
            timeout=opts.timeout,
            make_finding_fn=rules.make_cookie_attr_finding,
        )
        findings.extend(caf)
        stats["cookie_attr"] = castats

    if opts.probe_mode == "base_only":
        n_accounts = stats.get("login_matrix", {}).get("accounts", 0)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        if high:
            status, message = "fail", f"4-1 cookie flags: {high} high finding(s)"
        elif medium:
            status, message = "warn", f"4-1 cookie flags: {medium} medium finding(s)"
        else:
            status, message = "pass", f"4-1 login matrix + cookie flags — {n_accounts} account(s)"
        stats["findings"] = len(findings)
        stats["by_severity"] = {
            "high": high,
            "medium": medium,
            "info": sum(1 for f in findings if f.severity == "info"),
        }
        return ScanResult(
            status=status,
            message=message,
            stats=stats,
            findings=findings,
        )

    if not sessions:
        return ScanResult(
            status="skipped",
            message="No test-account login sessions — configure Test Accounts and run Verify",
            stats=stats,
            findings=findings,
        )

    endpoints = targets.collect_probe_endpoints(
        tree,
        raw_config=raw,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        max_endpoints=opts.max_endpoints,
        is_candidate_fn=rules.is_probe_candidate,
    )
    stats["endpoints_candidate"] = len(endpoints)

    from diagnosis.endpoint_auth import build_endpoint_auth_index, filter_cookie_probe_endpoints

    auth_index = build_endpoint_auth_index(ctx.data_dir)
    auth_info = rules.auth_requirement_info(auth_index)
    if auth_info:
        findings.append(auth_info)
        stats["auth_requirement"] = auth_info.evidence.get("summary")
    endpoints, auth_filter_stats = filter_cookie_probe_endpoints(
        endpoints,
        auth_index,
        auth_required_only=opts.auth_required_only,
    )
    stats["auth_filter"] = auth_filter_stats
    stats["endpoints"] = len(endpoints)

    if not endpoints:
        msg = "No auth-required probe endpoints — need Verify (anon vs authed) or disable auth_required_only"
        if not auth_index:
            msg = "No probe endpoints — need api-tree + verify-report (run Verify)"
        if opts.probe_mode == "base_only":
            msg = "base_only with no endpoints — configure sample/full for cookie probes"
        return ScanResult(status="skipped", message=msg, stats=stats, findings=findings)

    from diagnosis.progress_reporter import endpoint_progress, phase, prepare

    tamper_n = min(len(endpoints), opts.tamper_max_endpoints) if opts.tamper_enabled else 0
    probe_total = len(endpoints) if opts.cross_cookie_enabled else 0
    if opts.tamper_enabled:
        probe_total = max(probe_total, tamper_n)
    prepare(probe_total or len(endpoints), f"4-1: {len(endpoints)} endpoint(s)")

    if opts.cross_cookie_enabled:
        phase("4-1: cross-account cookie probes…", phase_name="httpx", done=0, total=len(endpoints))
        cf, cstats = probes.run_cross_cookie_probes(
            endpoints,
            sessions,
            auth_profiles=opts.auth_profiles,
            cross_session_pairs_fn=rules.cross_session_pairs,
            session_with_profile_fn=rules.session_with_profile,
            access_allowed_fn=rules.access_allowed,
            cross_cookie_leak_detected_fn=rules.cross_cookie_leak_detected,
            cross_cookie_leak_meta_fn=rules.cross_cookie_leak_meta,
            body_fingerprint_fn=rules.body_fingerprint,
            is_admin_api_path_fn=rules.is_admin_api_path,
            make_cross_finding_fn=rules.make_cross_cookie_finding,
            timeout=opts.timeout,
            max_pairs_per_endpoint=opts.max_pairs_per_endpoint,
            on_progress=endpoint_progress(total=len(endpoints), phase_name="httpx", prefix="cross "),
        )
        findings.extend(cf)
        stats["cross_cookie"] = cstats

    if opts.tamper_enabled:
        admin_eps = [ep for ep in endpoints if rules.is_admin_api_path(ep.path)]
        tamper_eps = admin_eps if admin_eps else endpoints
        phase(
            f"4-1: tamper probes ({min(len(tamper_eps), opts.tamper_max_endpoints)} endpoint(s))…",
            phase_name="httpx",
            done=0,
            total=min(len(tamper_eps), opts.tamper_max_endpoints),
        )
        tf, tstats = probes.run_tamper_probes(
            tamper_eps,
            sessions,
            auth_profiles=opts.auth_profiles,
            tampered_variants_fn=rules.tampered_auth_variants,
            access_allowed_fn=rules.access_allowed,
            make_tamper_finding_fn=rules.make_tamper_finding,
            build_isolated_confirm_ctx_fn=rules.build_isolated_confirm_ctx,
            tamper_label_allowed_fn=rules.tamper_label_targets_api_auth,
            timeout=opts.timeout,
            max_endpoints=opts.tamper_max_endpoints,
            max_variants_per_session=opts.max_tamper_variants_per_session,
            partial_cross_tamper=opts.partial_cross_tamper,
            on_progress=endpoint_progress(
                total=min(len(tamper_eps), opts.tamper_max_endpoints),
                phase_name="httpx",
                prefix="tamper ",
            ),
        )
        findings.extend(tf)
        stats["tamper"] = tstats

    findings = _dedupe_findings(findings)

    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    stats["findings"] = len(findings)
    stats["by_severity"] = {"high": high, "medium": medium, "info": sum(1 for f in findings if f.severity == "info")}

    if high:
        status, message = "fail", f"4-1 cookie: {high} high, {medium} medium finding(s)"
    elif medium:
        status, message = "warn", f"4-1 cookie review: {medium} medium finding(s)"
    else:
        status, message = "pass", "4-1 cookie cross/tamper checks completed — no high/medium issues"

    if len(sessions) < 2:
        message += " (need ≥2 sessions for cross-account probes)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
