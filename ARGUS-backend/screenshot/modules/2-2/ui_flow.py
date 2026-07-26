"""Resolve frontend UI navigation for 2-2 evidence capture."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_MODULE_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _MODULE_DIR.parents[2]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from models import EvidenceCase

_UI_ACTIONS = frozenset({"navigate", "scroll", "click", "screenshot"})


def _runtime_url(url: str) -> str:
    from inventory.net import probe_url

    return probe_url(str(url or ""))


def _path_only(url: str) -> str:
    return urlsplit(url).path.rstrip("/") or "/"


def _replay_ui_steps(case: EvidenceCase) -> list[dict[str, Any]]:
    evidence = dict(case.metadata.get("source_evidence") or {})
    replay = dict(evidence.get("replay") or {})
    steps = list(replay.get("steps") or [])
    return [
        step
        for step in steps
        if isinstance(step, dict) and str(step.get("action") or "") in _UI_ACTIONS
    ]


def _flow_ui_steps(case: EvidenceCase) -> list[dict[str, Any]]:
    from diagnosis.g22_replay import match_ui_flow, ui_flow_to_replay_steps

    method = str(case.baseline.method or case.attack.method or "GET")
    api_path = urlsplit(case.baseline.url or case.attack.url or "").path
    flow = match_ui_flow(method=method, path=api_path)
    if not flow:
        return []

    public_base = str(
        case.metadata.get("main_display_url")
        or case.metadata.get("main_url")
        or case.metadata.get("ui_display_url")
        or case.metadata.get("ui_url")
        or ""
    ).replace("host.docker.internal", "localhost").rstrip("/")
    if not public_base:
        return []

    return [
        {
            "action": step.action,
            "label": step.label,
            "url": step.url,
            "selector": step.selector,
        }
        for step in ui_flow_to_replay_steps(flow, public_base_url=public_base)
    ]


def resolve_ui_flow(case: EvidenceCase) -> dict[str, Any]:
    """
    Derive main/feature page URLs from finding replay steps or ui_flows.yaml.

    Returns empty dict when no UI flow is available.
    """
    main_base = str(case.metadata.get("main_url") or case.metadata.get("ui_url") or "")
    if not main_base:
        return {}

    ui_steps = _replay_ui_steps(case)
    source = "replay-steps"
    if not ui_steps:
        ui_steps = _flow_ui_steps(case)
        source = "ui-flows-yaml" if ui_steps else ""

    navigate_steps = [
        step for step in ui_steps if str(step.get("action")) == "navigate" and step.get("url")
    ]
    if not navigate_steps:
        return {}

    main_step = navigate_steps[0]
    main_url = _runtime_url(str(main_step.get("url") or main_base))

    feature_step = navigate_steps[-1]
    if len(navigate_steps) > 1:
        main_path = _path_only(str(main_step.get("url") or ""))
        for step in reversed(navigate_steps):
            if _path_only(str(step.get("url") or "")) != main_path:
                feature_step = step
                break

    feature_url = _runtime_url(str(feature_step.get("url") or main_url))
    feature_route = _path_only(str(feature_step.get("url") or ""))

    prep_steps: list[dict[str, Any]] = []
    seen_feature = False
    for step in ui_steps:
        action = str(step.get("action") or "")
        if action == "navigate":
            if _path_only(str(step.get("url") or "")) == feature_route:
                seen_feature = True
            continue
        if seen_feature and action in {"scroll", "click"}:
            prep_steps.append(step)

    return {
        "main_url": main_url,
        "feature_url": feature_url,
        "feature_route": feature_route,
        "prep_steps": prep_steps,
        "ui_route_source": source,
        "feature_label": str(feature_step.get("label") or feature_route),
    }


resolve_unauth_ui_flow = resolve_ui_flow
