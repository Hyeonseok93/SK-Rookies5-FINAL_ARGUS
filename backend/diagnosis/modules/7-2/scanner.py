"""Orchestrate guideline 7-2 directory listing scan."""

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
    mod_name = f"diag_g72_{name}"
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
    use_extended_wordlist: bool = False
    zap_enabled: bool = False
    zap_max_minutes: int = 15
    zap_seed_cap: int = 300


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_7_2") or raw.get("scan_7_2") or {}
    extra = cfg.get("extra_probe_paths") or cfg.get("probe_paths") or []
    mode = str(cfg.get("probe_mode", "base_only")).strip().lower()
    if mode not in ("base_only", "sample", "full"):
        mode = "base_only"
    return ScanOptions(
        timeout=float(cfg.get("timeout", 8.0)),
        extra_paths=[str(p) for p in extra if p],
        probe_mode=mode,  # type: ignore[arg-type]
        sample_size=max(1, min(int(cfg.get("sample_size", 20)), 500)),
        use_extended_wordlist=bool(cfg.get("use_extended_wordlist", True)),
        zap_enabled=bool(cfg.get("zap_enabled", False)),
        zap_max_minutes=max(1, min(int(cfg.get("zap_max_minutes", 15)), 120)),
        zap_seed_cap=max(50, min(int(cfg.get("zap_seed_cap", 300)), 5000)),
    )


def _primary_auth(raw: dict[str, Any]) -> dict[str, Any] | None:
    auth_cfg = raw.get("auth") or {}
    accounts = auth_cfg.get("accounts") or []
    if not accounts:
        return None
    logins = login_all_accounts(auth_cfg, accounts)
    return logins[0] if logins else None


def _collapse_listing_findings(
    items: list[DiagnosisFinding],
) -> tuple[list[DiagnosisFinding], dict[str, int]]:
    others: list[DiagnosisFinding] = []
    groups: dict[str, DiagnosisFinding] = {}
    url_sets: dict[str, set[str]] = {}
    label_sets: dict[str, set[str]] = {}

    for f in items:
        ev = f.evidence or {}
        if not ev.get("listing_type"):
            others.append(f)
            continue
        key = (
            f"{f.severity}|{ev.get('base_url')}|{ev.get('listing_type')}|"
            f"{ev.get('reason')}|{','.join(ev.get('matched_patterns') or [])}"
        )
        url = str(ev.get("url") or "")
        label = str(ev.get("label") or url)
        if key not in groups:
            groups[key] = f
            url_sets[key] = {url} if url else set()
            label_sets[key] = {label} if label else set()
            continue
        if url:
            url_sets[key].add(url)
        if label:
            label_sets[key].add(label)

    collapsed: list[DiagnosisFinding] = []
    raw_issues = 0
    for key, f in groups.items():
        urls = sorted(u for u in url_sets[key] if u)
        labels = sorted(l for l in label_sets[key] if l)
        raw_issues += max(1, len(urls))
        ev = dict(f.evidence or {})
        ev["affected_urls"] = urls
        ev["affected_count"] = len(urls) if urls else 1
        if urls:
            ev["url"] = urls[0]
        listing_type = ev.get("listing_type", "unknown")
        if len(urls) > 1:
            sample = labels[0] if labels else urls[0]
            message = (
                f"[7-2] Directory listing ({listing_type}): "
                f"{len(urls)} URL(s), e.g. `{sample}` — {ev.get('reason')}"
            )
        else:
            label = labels[0] if labels else ev.get("url", "")
            message = (
                f"[7-2] Directory listing ({listing_type}): `{label}` — {ev.get('reason')}"
            )
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


def run_g72_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    opts = _scan_options(ctx.raw_config)

    targets_mod = _load_local("targets")
    probes_mod = _load_local("probes")
    rules_mod = _load_local("listing_rules")

    probe_targets, target_meta = targets_mod.build_probe_targets(
        ctx.raw_config,
        data_dir=ctx.data_dir,
        probe_mode=opts.probe_mode,
        sample_size=opts.sample_size,
        extra_paths=opts.extra_paths,
        use_extended_wordlist=opts.use_extended_wordlist or opts.probe_mode == "full",
    )
    if not probe_targets:
        return ScanResult(
            status="skipped",
            message="No base URLs configured — add targets in dashboard Base URLs or config.yaml",
            stats={"targets": 0, "probe_mode": opts.probe_mode},
        )

    from diagnosis.progress_reporter import endpoint_progress, prepare, zap_phase

    prepare(len(probe_targets), f"7-2: {len(probe_targets)} URL(s)")

    findings, stats = probes_mod.run_listing_probes(
        probe_targets,
        classify_fn=rules_mod.classify_listing_response,
        remediation_fn=rules_mod.remediation_hint,
        fingerprint_fn=rules_mod._body_fingerprint,
        timeout=opts.timeout,
        probe_base_fn=targets_mod.probe_base_url,
        on_progress=endpoint_progress(total=len(probe_targets), phase_name="httpx", prefix="httpx "),
    )
    stats.update(target_meta)
    stats["probe_mode"] = opts.probe_mode
    stats["sample_size"] = opts.sample_size
    stats["httpx"] = {"probed": stats.get("probed", 0), "issues": stats.get("issues", 0)}

    priority_seed_urls: list[str] = []
    for finding in findings:
        ev = finding.evidence or {}
        listing_type = str(ev.get("listing_type") or "")
        if not listing_type or listing_type.startswith("zap_"):
            continue
        url = str(ev.get("url") or "").strip()
        if url:
            priority_seed_urls.append(url)

    zap_ran = False
    if opts.zap_enabled:
        base_urls = targets_mod.collect_base_urls(ctx.raw_config)
        try:
            zap_phase("ZAP 7-2 listing scan…")
            zap_mod = _load_local("zap_scan")
            zap_findings, zap_stats = zap_mod.run_zap_phase(
                ctx.raw_config,
                probe_targets,
                base_urls,
                _primary_auth(ctx.raw_config),
                max_minutes=opts.zap_max_minutes,
                seed_cap=opts.zap_seed_cap,
                priority_seed_urls=priority_seed_urls,
            )
            findings.extend(zap_findings)
            stats["zap"] = zap_stats
            zap_ran = True
        except ZapNotAvailableError as exc:
            stats["zap"] = {"error": str(exc)}
        except Exception as exc:
            stats["zap"] = {"error": str(exc)}

    findings, collapse_stats = _collapse_listing_findings(findings)
    stats.update(collapse_stats)

    status = _overall_status(findings)
    probed = stats.get("probed", 0)
    collapsed = stats.get("collapsed_issues", stats.get("issues", 0))

    if status == "pass" and stats.get("unreachable", 0) == probed:
        status = "error"
        message = "All probe targets unreachable"
    elif status == "pass":
        message = f"No directory listing on {probed} probe(s) ({opts.probe_mode})"
    else:
        message = (
            f"Directory listing: {collapsed} unique issue(s) from {probed} probe(s) "
            f"({opts.probe_mode})"
        )
    if stats.get("inventory_fallback"):
        message += " — api-tree missing, wordlist only"
    if not zap_ran and opts.zap_enabled:
        message += " (ZAP skipped/unavailable — httpx only)"

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
