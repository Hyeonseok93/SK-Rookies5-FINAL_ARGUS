"""Target and embedded-engine path resolution for diagnosis 1-6."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EngineTarget:
    engine_root: Path
    main_py: Path
    target: str
    api_spec: Path


def first_target(raw_config: dict[str, Any]) -> str:
    targets = raw_config.get("targets") or []
    for item in targets:
        if isinstance(item, dict) and item.get("base_url"):
            return str(item["base_url"]).rstrip("/")
    return "http://localhost:8080"


def resolve_engine_target(
    cfg: dict[str, Any],
    raw_config: dict[str, Any],
    module_dir: Path,
) -> EngineTarget:
    env_root = os.environ.get("ARGUS_W16_ROOT")
    engine_root = Path(cfg.get("w16_root") or env_root or (module_dir / "engine")).resolve()
    target = str(cfg.get("target") or first_target(raw_config)).rstrip("/")

    api_spec = Path(str(cfg.get("api_spec") or (engine_root / "swagger_api.json")))
    if not api_spec.is_absolute():
        api_spec = engine_root / api_spec

    return EngineTarget(
        engine_root=engine_root,
        main_py=engine_root / "main.py",
        target=target,
        api_spec=api_spec,
    )
