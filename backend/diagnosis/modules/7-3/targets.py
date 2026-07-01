"""Collect probe targets for 7-3 header scan."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls as collect_base_urls
from inventory.schema import ApiTree, Endpoint, build_full_url, split_path_query

ProbeMode = Literal["base_only", "sample", "full"]

DEFAULT_PROBE_PATHS = ("/",)


def load_api_tree(data_dir: Path | None) -> ApiTree | None:
    if data_dir is None:
        return None
    for name in ("api-tree-verified.json", "api-tree-ready.json", "api-tree.json"):
        path = data_dir / name
        if path.is_file():
            return ApiTree.load(path)
    return None


def probe_base_url(base_url: str) -> str:
    """Map localhost to probe host when ARGUS_PROBE_HOST is set (Docker)."""
    parsed = urlparse(base_url.rstrip("/"))
    host = (parsed.hostname or "").lower()
    if host not in ("localhost", "127.0.0.1"):
        return base_url.rstrip("/")
    probe_host = os.environ.get("ARGUS_PROBE_HOST", "").strip()
    if not probe_host:
        return base_url.rstrip("/")
    port = f":{parsed.port}" if parsed.port else ""
    scheme = parsed.scheme or "http"
    return f"{scheme}://{probe_host}{port}"


def _normalize_base(url: str) -> str:
    return url.rstrip("/").lower()


def _merge_paths(extra_paths: list[str] | None) -> list[str]:
    paths: list[str] = list(DEFAULT_PROBE_PATHS)
    for raw in extra_paths or []:
        p = raw.strip()
        if not p:
            continue
        p = p if p.startswith("/") else f"/{p}"
        if p not in paths:
            paths.append(p)
    return paths


def _endpoint_path(ep: Endpoint) -> str:
    path, _query = split_path_query(ep.path)
    return path or "/"


def _select_sample_paths(endpoints: list[Endpoint], limit: int) -> list[Endpoint]:
    by_path: dict[str, Endpoint] = {}
    for ep in endpoints:
        path = _endpoint_path(ep)
        prev = by_path.get(path)
        if prev is None:
            by_path[path] = ep
            continue
        if ep.method.upper() in ("GET", "HEAD") and prev.method.upper() not in ("GET", "HEAD"):
            by_path[path] = ep

    ordered_paths = sorted(by_path.keys(), key=lambda p: (p != "/", p))
    if limit <= 0 or len(ordered_paths) <= limit:
        return [by_path[p] for p in ordered_paths]

    picked: list[str] = []
    if ordered_paths and ordered_paths[0] == "/":
        picked.append("/")
        rest = ordered_paths[1:]
    else:
        rest = ordered_paths

    remaining = limit - len(picked)
    if remaining <= 0:
        return [by_path[p] for p in picked[:limit]]

    if rest:
        step = max(1, len(rest) // remaining)
        for i in range(0, len(rest), step):
            if len(picked) >= limit:
                break
            if rest[i] not in picked:
                picked.append(rest[i])
        if len(picked) < limit and rest[-1] not in picked:
            picked.append(rest[-1])

    return [by_path[p] for p in picked[:limit]]


def _inventory_endpoints_for_bases(tree: ApiTree, bases: list[str]) -> dict[str, list[Endpoint]]:
    base_set = {_normalize_base(b) for b in bases}
    grouped: dict[str, list[Endpoint]] = {b: [] for b in bases}
    for ep in tree.endpoints:
        nb = _normalize_base(ep.base_url)
        if nb not in base_set:
            continue
        for b in bases:
            if _normalize_base(b) == nb:
                grouped[b].append(ep)
                break
    return grouped


def _append_target(
    out: list[dict[str, str]],
    seen_urls: set[str],
    *,
    base_url: str,
    probe_url: str,
    label: str,
    source: str,
) -> None:
    if probe_url in seen_urls:
        return
    seen_urls.add(probe_url)
    out.append(
        {
            "base_url": base_url,
            "probe_url": probe_url,
            "label": label,
            "source": source,
        }
    )


def build_probe_urls(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
    probe_mode: ProbeMode = "base_only",
    sample_size: int = 20,
    extra_paths: list[str] | None = None,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """
    Return probe targets and selection metadata.

    probe_mode:
      - base_only: Dashboard base URLs × (/ + extra paths)
      - sample: above + up to sample_size unique paths per base from api-tree
      - full: all api-tree paths for matching bases (+ base paths if missing)
    """
    bases = collect_base_urls(raw_config)
    meta: dict[str, Any] = {
        "probe_mode": probe_mode,
        "sample_size": sample_size,
        "base_urls": len(bases),
        "inventory_endpoints": 0,
        "inventory_matched": 0,
        "inventory_fallback": False,
    }
    if not bases:
        return [], meta

    out: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    manual_paths = _merge_paths(extra_paths)

    for base in bases:
        probe_base = probe_base_url(base)
        for path in manual_paths:
            url = f"{probe_base.rstrip('/')}{path}"
            _append_target(
                out,
                seen_urls,
                base_url=base,
                probe_url=url,
                label=f"{base}{path}",
                source="base",
            )

    if probe_mode == "base_only":
        meta["targets"] = len(out)
        return out, meta

    tree = load_api_tree(data_dir)
    if tree is None or not tree.endpoints:
        meta["inventory_fallback"] = True
        meta["targets"] = len(out)
        return out, meta

    meta["inventory_endpoints"] = len(tree.endpoints)
    grouped = _inventory_endpoints_for_bases(tree, bases)

    for base, endpoints in grouped.items():
        meta["inventory_matched"] += len(endpoints)
        if probe_mode == "sample":
            selected = _select_sample_paths(endpoints, sample_size)
        else:
            selected = _select_sample_paths(endpoints, limit=0)

        probe_base = probe_base_url(base)
        for ep in selected:
            path, query = split_path_query(ep.path)
            url = build_full_url(probe_base, path, query)
            _append_target(
                out,
                seen_urls,
                base_url=base,
                probe_url=url,
                label=f"{base}{path}",
                source="inventory",
            )

    meta["targets"] = len(out)
    meta["inventory_selected"] = sum(1 for t in out if t.get("source") == "inventory")
    return out, meta
