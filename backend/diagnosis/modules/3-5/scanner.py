"""Orchestrate guideline 3-5 search-engine inventory scan."""

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
    mod_name = f"diag_g35_{name}"
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
    probe_mode: ProbeMode = "sample"
    sample_size: int = 50


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_3_5") or raw.get("scan_3_5") or {}
    extra = cfg.get("extra_probe_paths") or cfg.get("extra_sensitive_paths") or []
    mode = str(cfg.get("probe_mode", "sample")).strip().lower()
    if mode not in ("base_only", "sample", "full"):
        mode = "sample"
    return ScanOptions(
        timeout=float(cfg.get("timeout", 8.0)),
        extra_paths=[str(p) for p in extra if p],
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(1, min(int(cfg.get("sample_size", 50)), 500)),
    )


def run_g35_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    opts = _scan_options(ctx.raw_config)

    targets_mod = _load_local("targets")
    probes_mod = _load_local("probes")
    rules_mod = _load_local("robots_rules")

    bases = targets_mod.collect_base_urls(ctx.raw_config)
    robots_bases = targets_mod.bases_for_robots_inventory(bases, ctx.raw_config)
    if not bases:
        return ScanResult(
            status="skipped",
            message="No base URLs configured — add targets in dashboard Base URLs or config.yaml",
            stats={"targets": 0, "probe_mode": opts.probe_mode},
        )

    probe_targets, target_meta = targets_mod.build_probe_targets(
        ctx.raw_config,
        data_dir=ctx.data_dir,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        extra_paths=opts.extra_paths,
    )

    auth_sessions, _auth_meta = all_account_auths_with_meta(ctx.raw_config, data_dir=ctx.data_dir)
    auth_configured = len(auth_sessions) > 0

    from diagnosis.progress_reporter import phase, prepare

    page_passes = 1 + len(auth_sessions)
    grand_total = len(robots_bases) + len(probe_targets) * page_passes
    prepare(grand_total, f"3-5: {grand_total} probe(s)")
    progress_offset = 0

    def _page_progress(auth_label: str):
        def _cb(**kw: Any) -> None:
            nonlocal progress_offset
            local_done = int(kw.get("endpoints_done") or 0)
            done = progress_offset + local_done
            item = str(kw.get("endpoint_id") or auth_label)
            phase(
                f"pages {done}/{grand_total} · {item}",
                phase_name="httpx",
                done=done,
                total=grand_total,
            )

        return _cb

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = dict(target_meta)
    stats["probe_mode"] = opts.probe_mode
    stats["sample_size"] = opts.sample_size
    stats["auth_configured"] = auth_configured
    stats["auth_sessions"] = len(auth_sessions)

    robots_findings, robots_stats = probes_mod.run_robots_inventory(
        robots_bases,
        probe_base_fn=targets_mod.probe_base_url,
        parse_robots_fn=rules_mod.parse_robots_txt,
        timeout=opts.timeout,
        on_progress=lambda **kw: phase(
            f"robots {int(kw.get('endpoints_done') or 0)}/{len(robots_bases)}",
            phase_name="httpx",
            done=int(kw.get("endpoints_done") or 0),
            total=grand_total,
        ),
    )
    findings.extend(robots_findings)
    skipped_api = [b for b in bases if b not in robots_bases]
    robots_stats["skipped_api_bases"] = len(skipped_api)
    if skipped_api:
        robots_stats["skipped_api_base_urls"] = skipped_api
    stats["robots"] = robots_stats
    progress_offset += len(robots_bases)

    anon_findings, anon_stats = probes_mod.run_page_inventory(
        probe_targets,
        extract_signals_fn=rules_mod.extract_page_robots_signals,
        auth_mode="anonymous",
        request_headers=None,
        timeout=opts.timeout,
        on_progress=_page_progress("anonymous"),
    )
    findings.extend(anon_findings)
    stats["pages_anonymous"] = anon_stats
    progress_offset += len(probe_targets)

    auth_sessions_stats: list[dict[str, Any]] = []
    auth_noindex_total = 0
    for session in auth_sessions:
        auth_findings, auth_stats = probes_mod.run_page_inventory(
            probe_targets,
            extract_signals_fn=rules_mod.extract_page_robots_signals,
            auth_mode=session_auth_mode(session),
            request_headers=probe_request_headers(session),
            account_email=str(session.get("email") or "") or None,
            login_label=str(session.get("login_label") or "") or None,
            login_url=str(session.get("login_url") or "") or None,
            timeout=opts.timeout,
            on_progress=_page_progress(session_auth_mode(session)),
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
        auth_noindex_total += int(auth_stats.get("with_noindex", 0))

    if auth_sessions_stats:
        stats["pages_authenticated_sessions"] = auth_sessions_stats
        stats["pages_authenticated"] = {
            "sessions": len(auth_sessions_stats),
            "pages_probed": auth_sessions_stats[0].get("pages_probed", 0),
            "with_noindex": auth_noindex_total,
            "with_nofollow": sum(int(s.get("with_nofollow", 0)) for s in auth_sessions_stats),
            "without_robots_directive": sum(
                int(s.get("without_robots_directive", 0)) for s in auth_sessions_stats
            ),
        }
    else:
        stats["pages_authenticated"] = {"skipped": True, "reason": "no_test_account"}
        stats["pages_authenticated_sessions"] = []

    pages_n = anon_stats.get("pages_probed", 0)
    noindex_anon = anon_stats.get("with_noindex", 0)
    stats["httpx"] = {
        "robots_probed": robots_stats.get("robots_probed", 0),
        "pages_probed": pages_n,
        "passes": 1 + len(auth_sessions),
    }

    if pages_n == 0 and robots_stats.get("robots_probed", 0) == 0:
        status = "error"
        message = "No probes executed"
    elif anon_stats.get("unreachable", 0) == pages_n and pages_n > 0:
        status = "error"
        message = "All page probes unreachable"
    else:
        status = "pass"
        message = (
            f"Search-engine inventory — robots {robots_stats.get('robots_present', 0)}/"
            f"{robots_stats.get('robots_probed', 0)} present, "
            f"pages {pages_n} (anon noindex {noindex_anon}"
            f"{f', auth noindex {auth_noindex_total}' if auth_sessions else ''}) "
            f"({opts.probe_mode})"
        )
    if robots_stats.get("skipped_api_bases"):
        message += f" — robots skipped on {robots_stats['skipped_api_bases']} API base(s)"
    if stats.get("inventory_fallback"):
        message += " — api-tree missing, base `/` only"
    if not auth_configured:
        message += " — auth pass skipped (no test account)"
    elif auth_sessions:
        tags = ", ".join(session_probe_tag(s) for s in auth_sessions)
        message += f" — auth passes ({tags})"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
