"""Collect page probe targets for 3-5 — frontend URLs + per-base paths."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls, dedupe_probe_bases
from inventory.schema import ApiTree, Endpoint, split_path_query

ProbeMode = Literal["base_only", "sample", "full"]

_STATIC_EXT = frozenset(
    {
        "js", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp",
        "woff", "woff2", "ttf", "eot", "pdf", "zip", "gz", "mp4", "webm",
    }
)
_FRONTEND_PORTS = frozenset({3000, 4173, 4200, 5173, 8081})


def load_api_tree(data_dir: Path | None) -> ApiTree | None:
    if data_dir is None:
        return None
    for name in ("api-tree-verified.json", "api-tree-ready.json", "api-tree.json"):
        path = data_dir / name
        if path.is_file():
            return ApiTree.load(path)
    return None


def probe_base_url(base_url: str) -> str:
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


def _frontend_base_set(raw_config: dict[str, Any] | None) -> set[str]:
    raw = raw_config or {}
    seen: set[str] = set()
    inv = raw.get("inventory") or {}
    md = inv.get("markdown") or {}
    fe = str(md.get("frontend_base_url") or "").rstrip("/")
    if fe:
        seen.add(_normalize_base(fe))
    return seen


def collect_base_urls(raw_config: dict[str, Any] | None) -> list[str]:
    deduped, _ = dedupe_probe_bases(collect_probe_base_urls(raw_config))
    return deduped


def bases_for_robots_inventory(bases: list[str], raw_config: dict[str, Any] | None) -> list[str]:
    """robots.txt applies to public HTML origins only — skip API/WAS bases."""
    return [b for b in bases if is_frontend_base(b, raw_config)]


def _normalize_base(url: str) -> str:
    return url.rstrip("/").lower()


def is_frontend_base(base: str, raw_config: dict[str, Any] | None) -> bool:
    if _normalize_base(base) in _frontend_base_set(raw_config):
        return True
    parsed = urlparse(base.rstrip("/"))
    if parsed.port in _FRONTEND_PORTS:
        return True
    return False


def _endpoint_path(ep: Endpoint) -> str:
    path, _ = split_path_query(ep.path)
    return path or "/"


def _skip_static_asset(path: str) -> bool:
    path = path.split("?")[0]
    seg = path.rstrip("/").split("/")[-1].lower()
    if not seg or "." not in seg:
        return False
    ext = seg.rsplit(".", 1)[-1]
    return ext in _STATIC_EXT


def _include_page_endpoint(ep: Endpoint, *, is_frontend: bool) -> bool:
    if ep.method.upper() not in ("GET", "HEAD", ""):
        return False
    path = _endpoint_path(ep)
    if _skip_static_asset(path):
        return False
    if ep.kind == "frontend":
        return True
    if is_frontend:
        # SPA routes on frontend base (no /api JSON tree)
        lower = path.lower()
        if lower.startswith("/api/") or lower.startswith("/user-api/") or lower.startswith("/admin-api/"):
            return False
        return True
    # API/WAS base: skip REST JSON paths; keep rare HTML on same host
    lower = path.lower()
    if lower.startswith("/api/") or "/api/" in lower:
        return False
    return ep.kind == "frontend"


def _select_paths(endpoints: list[Endpoint], limit: int, *, is_frontend: bool) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for ep in endpoints:
        if not _include_page_endpoint(ep, is_frontend=is_frontend):
            continue
        path = _endpoint_path(ep)
        if path in seen:
            continue
        seen.add(path)
        paths.append(path)
    paths.sort(key=lambda p: (p != "/", p))
    if limit <= 0 or len(paths) <= limit:
        return paths
    step = max(1, len(paths) // limit)
    return [paths[i] for i in range(0, len(paths), step)][:limit]


def _inventory_by_base(tree: ApiTree, bases: list[str]) -> dict[str, list[Endpoint]]:
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


def build_probe_targets(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
    probe_mode: ProbeMode = "sample",
    sample_size: int = 50,
    extra_paths: list[str] | None = None,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    bases = collect_base_urls(raw_config)
    meta: dict[str, Any] = {
        "probe_mode": probe_mode,
        "sample_size": sample_size,
        "base_urls": len(bases),
        "inventory_endpoints": 0,
        "inventory_paths": 0,
        "frontend_bases": 0,
        "inventory_fallback": False,
    }
    if not bases:
        return [], meta

    extra: set[str] = {"/"}
    for raw in extra_paths or []:
        p = raw.strip()
        if p:
            extra.add(p if p.startswith("/") else f"/{p}")

    tree = load_api_tree(data_dir) if probe_mode != "base_only" else None
    grouped: dict[str, list[Endpoint]] = {}
    if tree and tree.endpoints:
        meta["inventory_endpoints"] = len(tree.endpoints)
        grouped = _inventory_by_base(tree, bases)
    elif probe_mode != "base_only":
        meta["inventory_fallback"] = True

    out: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    total_paths = 0

    for base in bases:
        is_fe = is_frontend_base(base, raw_config)
        if is_fe:
            meta["frontend_bases"] = int(meta.get("frontend_bases", 0)) + 1

        page_paths: set[str] = set(extra)
        if probe_mode != "base_only" and grouped:
            limit = sample_size if probe_mode == "sample" else 0
            for p in _select_paths(grouped.get(base, []), limit, is_frontend=is_fe):
                page_paths.add(p)

        probe_base = probe_base_url(base)
        for path in sorted(page_paths):
            url = f"{probe_base.rstrip('/')}{path if path.startswith('/') else f'/{path}'}"
            if url in seen_urls:
                continue
            seen_urls.add(url)
            total_paths += 1
            out.append(
                {
                    "base_url": base,
                    "probe_url": url,
                    "label": f"{base}{path}",
                    "path": path,
                    "source": "frontend" if is_fe else "base",
                    "base_kind": "frontend" if is_fe else "api",
                }
            )

    meta["inventory_paths"] = total_paths
    meta["targets"] = len(out)
    return out, meta
