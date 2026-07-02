"""Orchestration for diagnosis 1-6 using the embedded ARGUS W16 engine."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diagnosis.context import DiagnosisContext
from diagnosis.paths import section_evidence_dir
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from g16_auth import roles_from_config  # noqa: E402
from g16_classification import convert_findings, report_status  # noqa: E402
from g16_payloads import payload_sources  # noqa: E402
from g16_probes import latest_w16_run, run_engine  # noqa: E402
from g16_targets import resolve_engine_target  # noqa: E402


def _progress_update(update: dict[str, Any]) -> None:
    try:
        from app.services import diagnosis_progress

        diagnosis_progress.update(**update)
    except Exception:
        pass


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _cfg(ctx: DiagnosisContext) -> dict[str, Any]:
    return dict(ctx.raw_config.get("diagnosis_1_6") or ctx.raw_config.get("scan_1_6") or {})


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def run_g16_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    cfg = _cfg(ctx)
    engine_target = resolve_engine_target(cfg, ctx.raw_config, module_dir)
    if not engine_target.main_py.is_file():
        return ScanResult(
            status="skipped",
            message=f"Embedded W16 engine not found: {engine_target.main_py}",
            stats={
                "reason": "w16_engine_missing",
                "engine_root": str(engine_target.engine_root),
            },
        )
    if not engine_target.api_spec.is_file():
        return ScanResult(
            status="skipped",
            message=f"W16 api_spec not found: {engine_target.api_spec}",
            stats={
                "reason": "api_spec_missing",
                "api_spec": str(engine_target.api_spec),
            },
        )

    roles = roles_from_config(cfg)
    if not roles:
        return ScanResult(
            status="skipped",
            message="No test accounts for 1-6 W16 scan",
            stats={"reason": "roles_missing"},
        )

    evidence_dir = section_evidence_dir(ctx.data_dir, "1-6")
    output_dir = evidence_dir / "w16"
    output_dir.mkdir(parents=True, exist_ok=True)

    probe = run_engine(cfg, engine_target, output_dir, roles, progress_callback=_progress_update)
    run_dir = latest_w16_run(output_dir)
    stats: dict[str, Any] = {
        "engine": "argus-w16-embedded",
        "engine_root": str(engine_target.engine_root),
        "payload_sources": payload_sources(),
        "returncode": probe.returncode,
        "command": probe.command,
        "stdout_tail": probe.stdout[-4000:],
        "stderr_tail": probe.stderr[-4000:],
        "output_dir": str(output_dir),
        "run_dir": str(run_dir) if run_dir else "",
    }

    if probe.returncode != 0:
        return ScanResult(
            status="error",
            message=f"W16 process failed with exit code {probe.returncode}",
            stats=stats,
        )
    if run_dir is None:
        return ScanResult(
            status="error",
            message="W16 process completed but no run directory was produced",
            stats=stats,
        )

    summary = _load_json(run_dir / "summary.json", {})
    raw_findings = _load_json(run_dir / "raw_findings.json", [])
    if not isinstance(raw_findings, list):
        raw_findings = []

    stats.update(
        {
            "summary": summary,
            "raw_findings_count": len(raw_findings),
        }
    )

    limit = max(0, int(cfg.get("max_report_findings", 50)))
    findings = convert_findings(raw_findings, limit)
    status = report_status(findings)
    message = (
        f"1-6 W16 scan completed: {len(raw_findings)} raw finding(s), "
        f"{len(findings)} reported finding(s)"
    )
    return ScanResult(findings=findings, stats=stats, status=status, message=message)
