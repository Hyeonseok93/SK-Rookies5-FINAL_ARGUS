"""Resolve UI navigation flows for evidence replay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from diagnosis.replay.schema import ReplayStep

_FLOWS_PATH = Path(__file__).resolve().parent / "assets" / "ui_flows.yaml"


def _load_flows() -> list[dict[str, Any]]:
    if not _FLOWS_PATH.is_file():
        return []
    raw = yaml.safe_load(_FLOWS_PATH.read_text(encoding="utf-8")) or {}
    return list(raw.get("flows") or [])


def match_ui_flow(*, method: str, path: str) -> dict[str, Any] | None:
    m = method.upper()
    p = path.rstrip("/") or "/"
    for flow in _load_flows():
        match = flow.get("match") or {}
        if match.get("method", "").upper() != m:
            continue
        want = str(match.get("path", "")).rstrip("/")
        if p.endswith(want) or p == want:
            return flow
    return None


def ui_flow_to_replay_steps(
    flow: dict[str, Any],
    *,
    public_base_url: str,
    step_offset: int = 0,
) -> list[ReplayStep]:
    """Convert YAML ui flow to ReplayStep list (prefixed u01, u02, …)."""
    base = public_base_url.rstrip("/")
    out: list[ReplayStep] = []
    idx = step_offset
    for raw in flow.get("steps") or []:
        if not isinstance(raw, dict):
            continue
        idx += 1
        action = str(raw.get("action", "navigate"))
        step_id = f"u{idx:02d}_{action}"
        url = ""
        if raw.get("path"):
            url = f"{base}{raw['path']}" if str(raw["path"]).startswith("/") else str(raw["path"])
        out.append(
            ReplayStep(
                id=step_id,
                action=action,  # type: ignore[arg-type]
                label=str(raw.get("label") or action),
                url=url or None,
                selector=str(raw.get("selector") or "") or None,
                capture=list(raw.get("capture") or ["screenshot"]),
            )
        )
    return out
