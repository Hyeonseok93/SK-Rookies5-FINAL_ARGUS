"""Orchestrate guideline 1-3 scan (param value / hidden field manipulation).

Ported from ARGUS_Backend/scanners/param_manipulation/engine.py, rewired onto
the shared api-tree + DiagnosisContext architecture:
  Phase 1 (ZAP Ajax Spider collection) -> replaced by api-tree-verified.json
  Phase 2 (candidate/param classification) -> candidates.py + param_classify.py (rule-based, no LLM)
  Phase 3 (payload injection + 1st-pass anomaly detection) -> probes.py + compare.py (rule-based, no LLM)
  Phase 4 (LLM interpretation / final confirmation) -> llm_interpret.py

v2 note: LLM only runs in Phase 4, over the (small) set of RawFinding candidates
that Phase 3 already flagged deterministically. Detection itself never depends on
the LLM being up, and Ollama calls carry an explicit timeout — see llm_interpret.py
docstring for the ARGUS_Backend incident (unbounded LLM wait hung a celery worker
for hours) that this ordering + timeout fixes.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diagnosis.context import DiagnosisContext
from diagnosis.probe_auth import all_account_auths
from diagnosis.probe_transport import HttpxTransport
from diagnosis.replay.normalize import filter_endpoints_by_probe_bases
from diagnosis.result import DiagnosisFinding
from inventory.load import load_api_tree
from inventory.schema import ApiTree, Endpoint

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g13_{name}"
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
_mutations = _load_local("mutations")
_probes = _load_local("probes")
_compare = _load_local("compare")
_llm_interpret = _load_local("llm_interpret")


@dataclass
class ScanOptions:
    min_score: int = 2
    max_candidates: int = 80
    max_mutations_per_param: int = 5
    httpx_enabled: bool = True
    scan_all_inventory: bool = False
    llm_interpret_enabled: bool = True
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    candidates: list[Endpoint] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_1_3") or raw.get("scan_1_3") or {}
    return ScanOptions(
        min_score=int(cfg.get("min_score", 2)),
        max_candidates=int(cfg.get("max_candidates", 80)),
        max_mutations_per_param=int(cfg.get("max_mutations_per_param", 5)),
        httpx_enabled=bool(cfg.get("httpx_enabled", True)),
        scan_all_inventory=bool(cfg.get("scan_all_inventory", False)),
        llm_interpret_enabled=bool(cfg.get("llm_interpret_enabled", True)),
        ollama_base_url=str(cfg.get("ollama_base_url", "http://localhost:11434")),
        ollama_model=str(cfg.get("ollama_model", "qwen2.5:7b")),
    )


def _dedupe(findings: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    seen: set[str] = set()
    out: list[DiagnosisFinding] = []
    for f in findings:
        ev = f.evidence or {}
        key = f"{ev.get('rule_id')}|{ev.get('endpoint_id')}|{ev.get('param_name')}|{ev.get('payload')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def run_g13_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)
    assets_dir = module_dir / "assets"

    tree = load_api_tree(ctx.data_dir)
    if tree is None or not tree.endpoints:
        return ScanResult(
            status="error",
            message="No api-tree found — build inventory first (data/api-tree-ready.json)",
        )

    scoped = filter_endpoints_by_probe_bases(tree.endpoints, raw)
    if not scoped:
        return ScanResult(
            status="skipped",
            message="No api-tree endpoints match dashboard Base URLs",
            stats={"inventory_endpoints": len(tree.endpoints)},
        )
    scoped_tree = ApiTree(meta=tree.meta, endpoints=scoped)

    candidates, selection_mode = _candidates.select_scan_targets(
        scoped_tree,
        assets_dir=assets_dir,
        min_score=opts.min_score,
        max_count=0 if opts.scan_all_inventory else opts.max_candidates,
        scan_all_inventory=opts.scan_all_inventory,
    )
    stats: dict[str, Any] = {
        "candidates": _candidates.candidate_summary(candidates, mode=selection_mode),
        "inventory_endpoints": len(tree.endpoints),
        "selection_mode": selection_mode,
    }

    def _sensitive_params_fn(ep: Endpoint):
        return _candidates.sensitive_params(ep, assets_dir=assets_dir)

    design_findings = _design.review_design(candidates, sensitive_params_fn=_sensitive_params_fn)

    if not candidates:
        return ScanResult(
            status="no_targets",
            message="No 1-3 candidates in inventory — add POST/PUT/PATCH APIs with price/role/id-like fields or rebuild inventory",
            findings=design_findings,
            candidates=candidates,
            stats=stats,
        )

    from diagnosis.progress_reporter import endpoint_progress, prepare

    prepare(len(candidates), f"1-3: {len(candidates)} candidate(s)")

    httpx_findings: list[DiagnosisFinding] = []
    if opts.httpx_enabled:
        account_auths = all_account_auths(raw, data_dir=ctx.data_dir)
        auth = account_auths[0] if account_auths else None
        stats["auth"] = {"sessions": len(account_auths), "used": auth is not None}

        def _mutations_fn(category: str, original_value: Any):
            return _mutations.mutations_for(category, original_value, assets_dir=assets_dir)

        with HttpxTransport() as transport:
            probe_results, probe_stats = _probes.run_param_probes(
                candidates,
                transport=transport,
                auth=auth,
                sensitive_params_fn=_sensitive_params_fn,
                mutations_fn=_mutations_fn,
                max_mutations_per_param=opts.max_mutations_per_param,
                on_progress=endpoint_progress(total=len(candidates), phase_name="httpx", prefix="httpx "),
            )
        stats["httpx"] = probe_stats

        raw_findings = []
        for result in probe_results:
            raw_finding = _compare.detect_anomaly(
                ep=result["endpoint"],
                param_in=result["param_in"],
                param_name=result["param_name"],
                category=result["category"],
                payload_value=result["payload_value"],
                payload_description=result["payload_description"],
                baseline=result["baseline"],
                test=result["test"],
            )
            if raw_finding:
                raw_findings.append(raw_finding)
        stats["httpx"]["raw_findings"] = len(raw_findings)

        if opts.llm_interpret_enabled:
            httpx_findings = _llm_interpret.interpret_findings(
                raw_findings,
                ollama_base_url=opts.ollama_base_url,
                ollama_model=opts.ollama_model,
            )
        else:
            httpx_findings = _llm_interpret.promote_without_llm(raw_findings)

        httpx_findings = _dedupe(httpx_findings)
        stats["httpx"]["findings"] = len(httpx_findings)

    findings = design_findings + httpx_findings
    stats["httpx_findings"] = len(httpx_findings)
    stats["design_findings"] = len(design_findings)

    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")

    if high:
        status = "fail"
        message = f"1-3 findings: {high} high, {medium} medium ({len(candidates)} candidates scanned)"
    elif medium:
        status = "warn"
        message = f"1-3 review: {medium} medium findings ({len(candidates)} candidates)"
    else:
        status = "pass"
        message = f"No 1-3 issues detected ({len(candidates)} candidates)"

    if not opts.httpx_enabled:
        message += " (httpx probing disabled — design review only)"

    return ScanResult(findings=findings, candidates=candidates, stats=stats, status=status, message=message)
