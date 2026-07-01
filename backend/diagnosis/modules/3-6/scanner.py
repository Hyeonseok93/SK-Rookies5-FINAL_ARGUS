"""Orchestrate guideline 3-6 backup/test file scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from diagnosis.context import DiagnosisContext
from diagnosis.probe_auth import (
    all_account_auths_with_meta,
    probe_request_headers,
    session_auth_mode,
    session_probe_tag,
)
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent

ProbeMode = Literal["base_only", "sample", "full"]


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g36_{name}"
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
    extra_paths: list[str] = field(default_factory=list)
    probe_mode: ProbeMode = "base_only"
    sample_size: int = 20


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_3_6") or raw.get("scan_3_6") or {}
    extra = cfg.get("extra_probe_paths") or cfg.get("probe_paths") or []
    mode = str(cfg.get("probe_mode", "base_only")).strip().lower()
    if mode not in ("base_only", "sample", "full"):
        mode = "base_only"
    return ScanOptions(
        timeout=float(cfg.get("timeout", 8.0)),
        extra_paths=[str(p) for p in extra if p],
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(1, min(int(cfg.get("sample_size", 20)), 500)),
    )


def _collapse_file_findings(
    items: list[DiagnosisFinding],
) -> tuple[list[DiagnosisFinding], dict[str, int]]:
    others: list[DiagnosisFinding] = []
    groups: dict[str, DiagnosisFinding] = {}
    url_sets: dict[str, set[str]] = {}

    for f in items:
        ev = f.evidence or {}
        if not ev.get("file_type"):
            others.append(f)
            continue
        key = (
            f"{ev.get('auth_mode', 'anonymous')}|{f.severity}|{ev.get('base_url')}|"
            f"{ev.get('file_type')}|{ev.get('trigger')}|{ev.get('reason')}"
        )
        url = str(ev.get("url") or "")
        if key not in groups:
            groups[key] = f
            url_sets[key] = {url} if url else set()
            continue
        if url:
            url_sets[key].add(url)

    collapsed: list[DiagnosisFinding] = []
    raw_issues = 0
    for key, f in groups.items():
        urls = sorted(u for u in url_sets[key] if u)
        raw_issues += max(1, len(urls))
        ev = dict(f.evidence or {})
        ev["affected_urls"] = urls
        ev["affected_count"] = len(urls) if urls else 1
        if urls:
            ev["url"] = urls[0]
        path = ev.get("path") or urls[0] if urls else ""
        auth_tag = ev.get("auth_mode", "anonymous")
        if len(urls) > 1:
            message = (
                f"[3-6][{auth_tag}] Backup/test file ({ev.get('file_type')}): "
                f"{len(urls)} URL(s), e.g. `{path}` — {ev.get('reason')}"
            )
        else:
            message = f.message
        collapsed.append(DiagnosisFinding(severity=f.severity, message=message, evidence=ev))

    return others + collapsed, {
        "raw_issues": raw_issues,
        "collapsed_issues": len(collapsed),
    }


def _overall_status(findings: list[DiagnosisFinding]) -> str:
    severities = {f.severity for f in findings if f.severity in ("high", "medium", "low")}
    if "high" in severities or "medium" in severities:
        return "fail"
    if "low" in severities:
        return "warn"
    return "pass"


def run_g36_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    opts = _scan_options(ctx.raw_config)

    targets_mod = _load_local("targets")
    probes_mod = _load_local("probes")
    rules_mod = _load_local("file_rules")

    probe_targets, target_meta = targets_mod.build_probe_targets(
        ctx.raw_config,
        data_dir=ctx.data_dir,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        extra_paths=opts.extra_paths,
    )
    if not probe_targets:
        return ScanResult(
            status="skipped",
            message="No base URLs configured — add targets in dashboard Base URLs or config.yaml",
            stats={"targets": 0, "probe_mode": opts.probe_mode},
        )

    auth_sessions, _auth_meta = all_account_auths_with_meta(ctx.raw_config, data_dir=ctx.data_dir)
    auth_configured = len(auth_sessions) > 0

    from diagnosis.progress_reporter import phase, prepare

    page_passes = 1 + len(auth_sessions)
    grand_total = len(probe_targets) * page_passes
    prepare(grand_total, f"3-6: {grand_total} file probe(s)")
    progress_offset = 0

    def _file_progress(auth_label: str):
        def _cb(**kw: Any) -> None:
            nonlocal progress_offset
            local_done = int(kw.get("endpoints_done") or 0)
            done = progress_offset + local_done
            item = str(kw.get("endpoint_id") or auth_label)
            phase(
                f"files {done}/{grand_total} · {item}",
                phase_name="httpx",
                done=done,
                total=grand_total,
            )

        return _cb

    findings: list[DiagnosisFinding] = []
    anon_findings, anon_stats = probes_mod.run_file_probes(
        probe_targets,
        classify_fn=rules_mod.classify_file_response,
        remediation_fn=rules_mod.remediation_hint,
        fingerprint_fn=rules_mod._body_fingerprint,
        timeout=opts.timeout,
        probe_base_fn=targets_mod.probe_base_url,
        auth_mode="anonymous",
        request_headers=None,
        on_progress=_file_progress("anonymous"),
    )
    findings.extend(anon_findings)
    progress_offset += len(probe_targets)

    auth_sessions_stats: list[dict[str, Any]] = []
    for session in auth_sessions:
        auth_findings, auth_stats = probes_mod.run_file_probes(
            probe_targets,
            classify_fn=rules_mod.classify_file_response,
            remediation_fn=rules_mod.remediation_hint,
            fingerprint_fn=rules_mod._body_fingerprint,
            timeout=opts.timeout,
            probe_base_fn=targets_mod.probe_base_url,
            auth_mode=session_auth_mode(session),
            request_headers=probe_request_headers(session),
            account_email=str(session.get("email") or "") or None,
            login_label=str(session.get("login_label") or "") or None,
            login_url=str(session.get("login_url") or "") or None,
            on_progress=_file_progress(session_auth_mode(session)),
        )
        findings.extend(auth_findings)
        progress_offset += len(probe_targets)
        auth_sessions_stats.append(
            {
                "email": session.get("email"),
                "login_label": session.get("login_label"),
                "login_url": session.get("login_url"),
                **auth_stats,
            }
        )

    stats: dict[str, Any] = dict(target_meta)
    stats.update(anon_stats)
    stats["probe_mode"] = opts.probe_mode
    stats["sample_size"] = opts.sample_size
    stats["auth_configured"] = auth_configured
    stats["auth_sessions"] = len(auth_sessions)
    stats["anonymous"] = anon_stats
    if auth_sessions_stats:
        stats["authenticated_sessions"] = auth_sessions_stats
        stats["authenticated"] = {
            "sessions": len(auth_sessions_stats),
            "probed": auth_sessions_stats[0].get("probed", 0),
            "issues": sum(int(s.get("issues", 0)) for s in auth_sessions_stats),
        }
    else:
        stats["authenticated"] = {"skipped": True, "reason": "no_test_account"}
        stats["authenticated_sessions"] = []
    stats["httpx"] = {
        "probed": anon_stats.get("probed", 0),
        "issues": anon_stats.get("issues", 0),
        "passes": 1 + len(auth_sessions),
    }

    findings, collapse_stats = _collapse_file_findings(findings)
    stats.update(collapse_stats)
    stats["httpx_findings"] = sum(
        1 for f in findings if (f.evidence or {}).get("engine") == "httpx"
    )

    status = _overall_status(findings)
    probed = anon_stats.get("probed", 0)
    collapsed = stats.get("collapsed_issues", stats.get("issues", 0))

    if status == "pass" and anon_stats.get("unreachable", 0) == probed:
        status = "error"
        message = "All probe targets unreachable"
    elif status == "pass":
        message = f"No exposed backup/test files on {probed} probe(s) ({opts.probe_mode})"
    else:
        message = (
            f"Backup/test file exposure: {collapsed} unique issue(s) from {probed} probe(s) "
            f"({opts.probe_mode})"
        )
    if stats.get("inventory_fallback"):
        message += " — api-tree missing, wordlist only"
    if auth_sessions:
        tags = ", ".join(session_probe_tag(s) for s in auth_sessions)
        message += f" — auth passes ({tags})"
    elif not auth_configured:
        message += " — auth pass skipped (no test account)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
