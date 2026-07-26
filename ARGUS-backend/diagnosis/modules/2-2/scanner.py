"""Orchestrate guideline 2-2 v1 scan (generic)."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.zap_util import ZapNotAvailableError
from diagnosis.auth_session_pool import DiagnosisAuthPool
from diagnosis.endpoint_auth_passes import load_login_report
from diagnosis.context import DiagnosisContext
from diagnosis.paths import section_evidence_dir
from diagnosis.replay.normalize import collect_probe_base_urls, filter_endpoints_by_probe_bases
from diagnosis.g22_replay import G22ReplaySession as ReplaySession
from diagnosis.result import DiagnosisFinding
from inventory.schema import ApiTree, Endpoint
from inventory.load import load_api_tree

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g22_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_candidates = _load_local("candidates")
_design = _load_local("design_review")
_payloads = _load_local("payloads")
_probes = _load_local("probes")
_zap = _load_local("zap_scan")
_runner = _load_local("runner")
_transport = _load_local("transport")


@dataclass
class ScanOptions:
    min_score: int = 2
    max_candidates: int = 80
    zap_enabled: bool = False
    httpx_enabled: bool = True
    scan_all_inventory: bool = False
    dashboard_download_only: bool = False
    unauth_probe_enabled: bool = True
    idor_probe_enabled: bool = True
    forced_browse_enabled: bool = True
    design_review_enabled: bool = True
    zap_supplemental_enabled: bool = True


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    candidates: list[Endpoint] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    message: str = ""



def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_2_2") or raw.get("scan_2_2") or {}
    dashboard_only = bool(cfg.get("dashboard_download_only", False))
    return ScanOptions(
        min_score=int(cfg.get("min_score", 2)),
        max_candidates=int(cfg.get("max_candidates", 80)),
        zap_enabled=bool(cfg.get("zap_enabled", False)),
        httpx_enabled=bool(cfg.get("httpx_enabled", True)),
        scan_all_inventory=bool(cfg.get("scan_all_inventory", False)),
        dashboard_download_only=dashboard_only,
        unauth_probe_enabled=bool(cfg.get("unauth_probe_enabled", True)),
        idor_probe_enabled=(
            False if dashboard_only else bool(cfg.get("idor_probe_enabled", True))
        ),
        forced_browse_enabled=(
            False if dashboard_only else bool(cfg.get("forced_browse_enabled", True))
        ),
        design_review_enabled=(
            False if dashboard_only else bool(cfg.get("design_review_enabled", True))
        ),
        zap_supplemental_enabled=(
            False if dashboard_only else bool(cfg.get("zap_supplemental_enabled", True))
        ),
    )


def _finding_dedupe_key(f: DiagnosisFinding) -> str:
    ev = f.evidence or {}
    engine = ev.get("engine") or ev.get("source") or ""
    endpoint_id = ev.get("endpoint_id")
    param = ev.get("param")
    rule_id = ev.get("rule_id")
    plugin_id = ev.get("plugin_id", "")
    if endpoint_id and param and rule_id:
        return f"{engine}|{rule_id}|{endpoint_id}|{param}|{ev.get('classification')}"
    if plugin_id and rule_id:
        return f"{engine}|{rule_id}|{plugin_id}|{ev.get('url')}|{ev.get('param')}"
    return f"{engine}|{f.severity}:{f.message}"


def _dedupe_within_engine(items: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    seen: set[str] = set()
    out: list[DiagnosisFinding] = []
    for f in items:
        key = _finding_dedupe_key(f)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _engine_of(f: DiagnosisFinding) -> str:
    ev = f.evidence or {}
    return str(ev.get("engine") or ev.get("source") or "other")


def run_g22_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)
    assets = module_dir / "assets"

    inventory_count = 0
    param_discovery: dict[str, Any] = {}
    if opts.dashboard_download_only:
        candidates, selection_mode = _candidates.select_dashboard_download_candidates_only(raw)
        if not candidates:
            return ScanResult(
                status="skipped",
                message=(
                    "Attack Surface → Download Endpoints에 다운로드 API를 등록하세요 "
                    "(Build Attack Tree 패널)"
                ),
                stats={"selection_mode": selection_mode, "dashboard_download_endpoints": 0},
            )
        from app.services.download_param_discover import enrich_dashboard_download_endpoints
        from inventory.load import load_param_discovery_api_tree

        tree, tree_source = load_param_discovery_api_tree(ctx.data_dir)
        param_discovery = enrich_dashboard_download_endpoints(
            candidates,
            data_dir=ctx.data_dir,
            tree=tree,
        )
        if tree_source:
            param_discovery["api_tree_source"] = tree_source
    else:
        tree = load_api_tree(ctx.data_dir)
        if tree is None or not tree.endpoints:
            return ScanResult(
                status="error",
                message="No api-tree found — build inventory first (data/api-tree-ready.json)",
            )

        inventory_count = len(tree.endpoints)
        scoped = filter_endpoints_by_probe_bases(tree.endpoints, raw)
        if not scoped:
            return ScanResult(
                status="skipped",
                message="No api-tree endpoints match dashboard Base URLs",
                stats={"inventory_endpoints": inventory_count},
            )
        scoped_tree = ApiTree(meta=tree.meta, endpoints=scoped)

        candidates, selection_mode = _candidates.select_scan_targets(
            scoped_tree,
            min_score=opts.min_score,
            max_count=0 if opts.scan_all_inventory else opts.max_candidates,
            scan_all_inventory=opts.scan_all_inventory,
        )
        candidates = _candidates.merge_dashboard_download_candidates(candidates, raw)

    dashboard_downloads = sum(1 for ep in candidates if "dashboard-download" in ep.tags)
    design_findings = (
        _design.review_design(candidates) if opts.design_review_enabled else []
    )
    stats: dict[str, Any] = {
        "candidates": _candidates.candidate_summary(candidates, mode=selection_mode),
        "inventory_endpoints": inventory_count,
        "selection_mode": selection_mode,
        "dashboard_download_endpoints": dashboard_downloads,
        "checks_enabled": {
            "traversal": opts.httpx_enabled or opts.zap_enabled,
            "unauth_download": opts.unauth_probe_enabled,
            "idor": opts.idor_probe_enabled,
            "forced_browse": opts.forced_browse_enabled,
            "design_review": opts.design_review_enabled,
            "zap_supplemental": opts.zap_supplemental_enabled and opts.zap_enabled,
        },
    }
    if param_discovery:
        stats["param_discovery"] = param_discovery

    from diagnosis.progress_reporter import endpoint_progress, prepare, zap_phase

    prepare(len(candidates), f"2-2: {len(candidates)} candidate(s)")

    auth_pool: DiagnosisAuthPool | None = None
    auth = None
    account_auths: list[dict[str, Any]] = []
    if opts.httpx_enabled or opts.zap_enabled or opts.unauth_probe_enabled or opts.idor_probe_enabled:
        auth_pool = DiagnosisAuthPool(raw, data_dir=ctx.data_dir)
        account_auths = auth_pool.sessions()
        auth = auth_pool.primary()
    if opts.dashboard_download_only and candidates and auth_pool:
        needs_live = any(
            "dashboard-download" in (ep.tags or [])
            and not any(inp.in_ in ("body", "form") for inp in ep.request_params)
            for ep in candidates
        )
        if needs_live and opts.httpx_enabled:
            from app.services.download_param_discover import enrich_dashboard_download_endpoints
            from inventory.load import load_param_discovery_api_tree

            live_tree, live_tree_source = load_param_discovery_api_tree(ctx.data_dir)
            with _transport.HttpxTransport() as live_transport:
                param_discovery["live_pass"] = enrich_dashboard_download_endpoints(
                    candidates,
                    data_dir=ctx.data_dir,
                    tree=live_tree,
                    transport=live_transport,
                    auth=auth,
                )
            if live_tree_source:
                param_discovery["live_pass"]["api_tree_source"] = live_tree_source
            stats["param_discovery"] = param_discovery
    login_report = load_login_report(ctx.data_dir, raw)
    base_urls = collect_probe_base_urls(raw)
    if not base_urls:
        base_urls = sorted({ep.base_url.rstrip("/") for ep in candidates if ep.base_url})

    seed_urls = _probes.seed_urls_from_candidates(candidates, auth)
    traversal_payloads = _payloads.load_traversal_payloads(assets)
    browse_paths = (
        _payloads.load_forced_browse_paths(assets) if opts.forced_browse_enabled else []
    )

    replay_session = ReplaySession(
        section_id="2-2",
        artifacts_root=section_evidence_dir(ctx.data_dir, "2-2"),
        raw_config=raw,
        account_auth=auth,
    )

    httpx_findings: list[DiagnosisFinding] = []
    zap_findings: list[DiagnosisFinding] = []

    if opts.httpx_enabled:
        with _transport.HttpxTransport() as httpx_transport:
            hf, hstats = _runner.run_2_2_probes(
                httpx_transport,
                engine="httpx",
                candidates=candidates,
                base_urls=base_urls,
                traversal_payloads=traversal_payloads,
                browse_paths=browse_paths,
                auth=auth,
                account_auths=account_auths,
                unauth_probe_enabled=opts.unauth_probe_enabled,
                idor_probe_enabled=opts.idor_probe_enabled,
                forced_browse_enabled=opts.forced_browse_enabled,
                idor_seeds=(raw.get("diagnosis_2_2") or raw.get("scan_2_2") or {}).get("idor_seeds"),
                replay_session=replay_session,
                auth_pool=auth_pool,
                login_report=login_report,
                on_progress=endpoint_progress(
                    total=len(candidates), phase_name="httpx", prefix="httpx "
                ),
            )
        httpx_findings = _dedupe_within_engine(hf)
        stats["httpx"] = hstats
        stats["httpx"]["findings"] = len(httpx_findings)

    zap_ran = False
    if opts.zap_enabled and candidates:
        try:
            if auth_pool:
                auth_pool.ensure_valid()
                auth = auth_pool.primary()
                account_auths = auth_pool.sessions()
            zap_phase("ZAP 2-2 traversal scan…")
            zf, zap_stats = _zap.run_zap_phase(
                raw,
                candidates,
                seed_urls,
                base_urls,
                auth,
                traversal_payloads=traversal_payloads,
                browse_paths=browse_paths,
                unauth_probe_enabled=opts.unauth_probe_enabled,
                account_auths=account_auths,
                idor_probe_enabled=opts.idor_probe_enabled,
                forced_browse_enabled=opts.forced_browse_enabled,
                zap_supplemental_enabled=opts.zap_supplemental_enabled,
                idor_seeds=(raw.get("diagnosis_2_2") or raw.get("scan_2_2") or {}).get("idor_seeds"),
            )
            zap_findings = _dedupe_within_engine(zf)
            stats["zap"] = zap_stats
            stats["zap"]["findings"] = len(zap_findings)
            zap_ran = True
        except ZapNotAvailableError as exc:
            stats["zap"] = {"error": str(exc)}
        except Exception as exc:
            stats["zap"] = {"error": str(exc)}

    findings = design_findings + httpx_findings + zap_findings
    stats["httpx_findings"] = len(httpx_findings)
    stats["zap_findings"] = len(zap_findings)
    if auth_pool:
        stats["auth_refresh_count"] = auth_pool.refresh_count
        stats["auth_source"] = auth_pool.meta.get("source")

    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")

    if high:
        status = "fail"
        message = f"2-2 findings: {high} high, {medium} medium ({len(candidates)} candidates scanned)"
    elif medium:
        status = "warn"
        message = f"2-2 review: {medium} medium findings ({len(candidates)} candidates)"
    else:
        status = "pass" if candidates else "no_targets"
        message = (
            f"No 2-2 issues detected ({len(candidates)} candidates)"
            if candidates
            else (
                "Attack Surface → Download Endpoints에 다운로드 API를 등록하세요"
                if opts.dashboard_download_only
                else "No 2-2 candidates in inventory — add export/download/file APIs or rebuild inventory"
            )
        )

    if not zap_ran and opts.zap_enabled:
        message += " (ZAP skipped/unavailable — httpx + design review only)"

    return ScanResult(
        findings=findings,
        candidates=candidates,
        stats=stats,
        status=status,
        message=message,
    )
