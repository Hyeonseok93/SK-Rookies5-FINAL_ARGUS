"""Target and embedded-engine path resolution for diagnosis 1-6."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from g16_inventory import api_tree_to_openapi_spec, latest_openapi_spec, preferred_api_tree_base_url, resolve_target
from inventory.net import probe_base_url

# Swagger UI "Try it out"이 채워주는 기본 placeholder 값들.
# 사용자가 실제 값으로 바꾸지 않고 그대로 Execute하면 이 문자열들이 그대로 넘어온다.
_PLACEHOLDER_VALUES = {"string", "", None}


def _real_value(value: Any) -> Any:
    """빈 값이나 Swagger placeholder("string")를 걸러내고, 진짜 값만 통과시킨다."""
    if isinstance(value, str) and value.strip().lower() in _PLACEHOLDER_VALUES:
        return None
    return value


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
    data_dir: Path | None = None,
) -> EngineTarget:
    env_root = os.environ.get("ARGUS_W16_ROOT")
    engine_root = Path(_real_value(cfg.get("w16_root")) or env_root or (module_dir / "engine")).resolve()
    explicit_target = _real_value(cfg.get("target"))
    if data_dir is not None and not explicit_target and not _real_value(cfg.get("api_spec")):
        target = preferred_api_tree_base_url(data_dir) or resolve_target(data_dir, raw_config, None)
    else:
        target = (
            resolve_target(data_dir, raw_config, explicit_target)
            if data_dir is not None
            else str(explicit_target or first_target(raw_config)).rstrip("/")
        )

    # Under Docker (ARGUS_PROBE_HOST set) rewrite localhost -> host.docker.internal
    # so the embedded W16 engine reaches the target on the host, not inside its
    # own container. No-op for native runs. Applied before the spec is generated
    # so servers[0].url and per-endpoint bases inherit the probe host too.
    target = probe_base_url(target)

    explicit_spec = _real_value(cfg.get("api_spec"))
    api_tree_spec = None
    if not explicit_spec and data_dir is not None:
        api_tree_spec, _api_tree_meta = api_tree_to_openapi_spec(data_dir, target)
    dashboard_spec = latest_openapi_spec(data_dir) if data_dir is not None else None
    api_spec = Path(str(explicit_spec or api_tree_spec or dashboard_spec or (engine_root / "swagger_api.json")))
    if not api_spec.is_absolute():
        api_spec = engine_root / api_spec

    return EngineTarget(
        engine_root=engine_root,
        main_py=engine_root / "main.py",
        target=target,
        api_spec=api_spec,
    )