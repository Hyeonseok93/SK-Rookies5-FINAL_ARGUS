"""Orchestrate guideline 3-4 admin separation scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g34_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def run_g34_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    targets = _load_local("targets")
    rules = _load_local("separation_rules")

    tree = targets.load_api_tree(ctx.data_dir)
    bases = targets.collect_base_urls(ctx.raw_config)
    login_report = targets.load_login_report(ctx.data_dir, ctx.raw_config)
    extra_admin_hosts = targets.extra_admin_hosts_from_config(ctx.raw_config)

    # Register admin hosts from dashboard base URLs (e.g. https://admin.onde.click)
    for base in bases:
        host, _, _ = rules.parse_host_port(base)
        if rules.is_admin_subdomain_host(host):
            extra_admin_hosts.append(host)

    if not login_report and tree is None and not bases:
        return ScanResult(
            status="skipped",
            message="No login entries or api-tree — run Verify and configure login URLs first",
            stats={"login_entries": 0},
        )

    from diagnosis.progress_reporter import phase, prepare

    prepare(1, "3-4: analyzing admin separation…")
    phase("3-4: inventory + login matrix", phase_name="analyzing", done=0, total=1)

    login_entries = list(login_report.get("login_entries") or []) if login_report else []
    inventory = rules.slice_inventory(tree, extra_bases=bases)

    findings, stats = rules.analyze_separation(
        login_entries=login_entries,
        inventory=inventory,
        extra_admin_hosts=extra_admin_hosts,
    )
    phase("3-4: analysis complete", phase_name="analyzing", done=1, total=1)

    stats["bases"] = bases
    stats["extra_admin_hosts"] = sorted(set(extra_admin_hosts))

    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    info = sum(1 for f in findings if f.severity == "info")

    has_separation_pass = any(
        (f.evidence or {}).get("rule_id") == "3-4-host-separated" for f in findings
    )

    if high:
        status = "fail"
        message = f"3-4 separation: {high} high, {medium} medium finding(s)"
    elif medium:
        status = "warn"
        message = f"3-4 separation review: {medium} medium finding(s)"
    elif has_separation_pass:
        status = "pass"
        message = "Admin host separated by subdomain; review info findings for path exposure"
    else:
        status = "pass" if not medium and not high else "warn"
        message = "3-4 separation checks completed — see findings"

    if not login_entries:
        message += " (no login entries — inventory-only)"
    stats["findings"] = len(findings)
    stats["by_severity"] = {"high": high, "medium": medium, "info": info}

    return ScanResult(findings=findings, stats=stats, status=status, message=message)
