"""Load findings from section reports and run evidence replay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.services.test_accounts_service import load_test_accounts
from app.workspace import require_data_dir
from diagnosis.replay.runner import ReplayRunResult, run_replay_plan
from diagnosis.replay.schema import ReplayPlan
from diagnosis.context import DiagnosisContext
from diagnosis.paths import resolve_report_path, section_evidence_dir
from diagnosis.registry import get_module


def _report_path(section_id: str, module_dir: Path, data_dir: Path) -> Path:
    ctx = DiagnosisContext(data_dir=data_dir)
    return resolve_report_path(ctx=ctx, section_id=section_id, module_dir=module_dir)


def list_replayable_findings(section_id: str, *, data_dir: Path | None = None) -> list[dict[str, Any]]:
    data_dir = require_data_dir(data_dir)
    mod = get_module(section_id)
    if mod is None:
        return []
    path = _report_path(section_id, mod.module_dir, data_dir)
    if not path.is_file():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: list[dict[str, Any]] = []
    for f in raw.get("findings") or []:
        if not isinstance(f, dict):
            continue
        ev = f.get("evidence") or {}
        replay = ev.get("replay")
        if not replay or not ev.get("replayable", True):
            continue
        out.append(
            {
                "severity": f.get("severity"),
                "message": f.get("message"),
                "finding_id": ev.get("finding_id") or replay.get("finding_id"),
                "rule_id": ev.get("rule_id") or replay.get("rule_id"),
                "replay": replay,
            }
        )
    return out


def run_section_replay(
    section_id: str,
    *,
    data_dir: Path | None = None,
    finding_id: str | None = None,
    raw_config: dict[str, Any] | None = None,
    use_playwright: bool = True,
) -> list[ReplayRunResult]:
    data_dir = require_data_dir(data_dir)
    mod = get_module(section_id)
    if mod is None:
        raise KeyError(f"Unknown section: {section_id}")

    artifacts_root = section_evidence_dir(data_dir, section_id)
    findings = list_replayable_findings(section_id, data_dir=data_dir)
    if finding_id:
        findings = [f for f in findings if f.get("finding_id") == finding_id]
    if not findings:
        return []

    accounts = load_test_accounts(data_dir).get("accounts") or []
    results: list[ReplayRunResult] = []
    for row in findings:
        plan = ReplayPlan.from_dict(row["replay"])
        results.append(
            run_replay_plan(
                plan,
                artifacts_root=artifacts_root,
                raw_config=raw_config,
                test_accounts=accounts,
                use_playwright=use_playwright,
            )
        )
    return results
