"""Endpoint targets for 6-1 error-page probes."""

from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import Any, Literal

from diagnosis.replay.normalize import collect_probe_base_urls, filter_endpoints_by_probe_bases
from inventory.schema import ApiTree, Endpoint

ProbeMode = Literal["sample", "full"]


def load_api_tree(data_dir: Path | None) -> ApiTree | None:
    if data_dir is None:
        return None
    for name in ("api-tree-verified.json", "api-tree-ready.json", "api-tree.json"):
        path = data_dir / name
        if path.is_file():
            return ApiTree.load(path)
    return None


def _stable_sample_key(ep: Endpoint) -> int:
    digest = hashlib.sha256(ep.endpoint_id.encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def select_endpoints(
    endpoints: list[Endpoint],
    *,
    probe_mode: ProbeMode,
    sample_size: int,
    max_endpoints: int,
) -> tuple[list[Endpoint], dict[str, Any]]:
    api_eps = [ep for ep in endpoints if ep.kind == "api" or ep.path.startswith("/api")]
    api_eps.sort(key=lambda e: (_stable_sample_key(e), e.endpoint_id))

    total = len(api_eps)
    if probe_mode == "full":
        chosen = api_eps[:max_endpoints] if max_endpoints > 0 else api_eps
    else:
        n = min(sample_size, len(api_eps))
        if n < len(api_eps):
            rng = random.Random(61)
            indices = sorted(rng.sample(range(len(api_eps)), n))
            chosen = [api_eps[i] for i in indices]
        else:
            chosen = api_eps
        if max_endpoints > 0:
            chosen = chosen[:max_endpoints]

    return chosen, {
        "endpoints_total": total,
        "endpoints_selected": len(chosen),
        "probe_mode": probe_mode,
        "sample_size": sample_size,
        "max_endpoints": max_endpoints,
    }


def build_endpoint_targets(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None,
    probe_mode: ProbeMode,
    sample_size: int,
    max_endpoints: int,
) -> tuple[list[Endpoint], dict[str, Any]]:
    tree = load_api_tree(data_dir)
    bases = collect_probe_base_urls(raw_config)
    meta: dict[str, Any] = {
        "base_urls": bases,
        "inventory": tree is not None,
    }
    if not bases:
        meta["message"] = "no_base_urls"
        return [], meta
    if tree is None:
        meta["message"] = "no_api_tree"
        return [], meta

    filtered = filter_endpoints_by_probe_bases(tree.endpoints, raw_config)
    chosen, sel_meta = select_endpoints(
        filtered,
        probe_mode=probe_mode,
        sample_size=sample_size,
        max_endpoints=max_endpoints,
    )
    meta.update(sel_meta)
    return chosen, meta
