"""Endpoint targets for 5-2 PII probes."""

from __future__ import annotations

import hashlib
import os
import random
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls, filter_endpoints_by_probe_bases
from inventory.schema import ApiTree, Endpoint
from inventory.load import load_api_tree
from inventory.net import probe_base_url

ProbeMode = Literal["sample", "full"]

_API_PORTS = frozenset({8080, 8081, 8443, 8000, 3000})




def _stable_sample_key(ep: Endpoint) -> int:
    digest = hashlib.sha256(ep.endpoint_id.encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def _endpoint_port(ep: Endpoint) -> int:
    parsed = urlparse(ep.base_url or "")
    if parsed.port is not None:
        return parsed.port
    return 443 if (parsed.scheme or "http") == "https" else 80


def _api_probe_base_rank(ep: Endpoint) -> int:
    """Prefer direct API origins over Vite frontend (HTML) for PII JSON scans."""
    port = _endpoint_port(ep)
    path = (ep.path or "").lower()
    is_admin = path.startswith("/api/v1/admin") or path.startswith("/api/admin")
    if is_admin:
        if port == 8081:
            return 0
        if port == 8080:
            return 2
        if port == 5173:
            return 8
        return 4
    if path.startswith("/api"):
        if port == 8080:
            return 1
        if port == 8081:
            return 3
        if port == 5173:
            return 9
        return 5
    if port in _API_PORTS:
        return 6
    if port == 5173:
        return 10
    return 7


def dedupe_api_probe_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """One probe row per method+path — pick direct API base (8080/8081) over SPA gateway."""
    best: dict[str, Endpoint] = {}
    for ep in endpoints:
        key = f"{ep.method.upper()}:{ep.path}"
        current = best.get(key)
        if current is None or _api_probe_base_rank(ep) < _api_probe_base_rank(current):
            best[key] = ep
    return list(best.values())


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
            rng = random.Random(52)
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
    deduped = dedupe_api_probe_endpoints(filtered)
    chosen, sel_meta = select_endpoints(
        deduped,
        probe_mode=probe_mode,
        sample_size=sample_size,
        max_endpoints=max_endpoints,
    )
    meta.update(sel_meta)
    meta["endpoints_before_dedupe"] = len(filtered)
    meta["endpoints_after_dedupe"] = len(deduped)
    return chosen, meta
