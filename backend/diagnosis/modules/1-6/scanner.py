"""Orchestration for diagnosis 1-6 using the embedded ARGUS W16 engine."""

from __future__ import annotations

import json
import asyncio
import importlib.util
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


def _run_screenshot_capture(ctx: DiagnosisContext, cfg: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    if cfg.get("screenshot_enabled") is False:
        return {"enabled": False, "reason": "disabled_by_config"}

    screenshot_dir = ctx.data_dir.parent / "screenshot" / "modules" / "1-6"
    runner_path = screenshot_dir / "runner.py"
    if not runner_path.is_file():
        return {
            "enabled": False,
            "reason": "runner_missing",
            "runner": str(runner_path),
        }

    if str(screenshot_dir) not in sys.path:
        sys.path.insert(0, str(screenshot_dir))

    spec = importlib.util.spec_from_file_location("w16_screenshot_runner", runner_path)
    if spec is None or spec.loader is None:
        return {
            "enabled": False,
            "reason": "runner_load_failed",
            "runner": str(runner_path),
        }

    try:
        module = importlib.util.module_from_spec(spec)
        sys.modules["w16_screenshot_runner"] = module
        spec.loader.exec_module(module)
        no_capture = bool(cfg.get("screenshot_plan_only", False))
        manifest = asyncio.run(module.run_capture(run_dir, no_capture=no_capture))
        return {
            "enabled": True,
            "status": manifest.get("status"),
            "plan": str(run_dir / "screenshot_plan.json"),
            "manifest": str(run_dir / "screenshot_manifest.json"),
            "stats": manifest.get("stats", {}),
            "error": manifest.get("error"),
        }
    except Exception as exc:
        return {
            "enabled": True,
            "status": "error",
            "runner": str(runner_path),
            "error": str(exc),
        }


def run_g16_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    cfg = _cfg(ctx)
    engine_target = resolve_engine_target(cfg, ctx.raw_config, module_dir, data_dir=ctx.data_dir)
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

    _progress_update(
        {
            "phase": "running",
            "message": "1-6 embedded W16 engine starting",
            "percent": 3,
        }
    )
    probe = run_engine(
        cfg,
        engine_target,
        output_dir,
        roles,
        data_dir=ctx.data_dir,
        progress_callback=_progress_update,
    )
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

    _progress_update(
        {
            "phase": "running",
            "message": "1-6 generating evidence screenshots",
            "percent": 96,
        }
    )
    screenshot_stats = _run_screenshot_capture(ctx, cfg, run_dir)
    stats["screenshots"] = screenshot_stats

    limit = max(0, int(cfg.get("max_report_findings", 50)))
    findings = convert_findings(raw_findings, limit)
    status = report_status(findings)
    message = (
        f"1-6 W16 scan completed: {len(raw_findings)} raw finding(s), "
        f"{len(findings)} reported finding(s)"
    )
    return ScanResult(findings=findings, stats=stats, status=status, message=message)
