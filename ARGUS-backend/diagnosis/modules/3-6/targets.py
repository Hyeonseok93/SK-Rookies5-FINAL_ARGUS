"""Collect backup/test file probe targets for 3-6."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls, dedupe_probe_bases
from inventory.schema import ApiTree, Endpoint, split_path_query
from inventory.load import load_api_tree
from inventory.net import probe_base_url

ProbeMode = Literal["base_only", "sample", "full"]

_MODULE_DIR = Path(__file__).resolve().parent
_ASSETS = _MODULE_DIR / "assets" / "backup-test-files.txt"
_FORCED_BROWSE = _MODULE_DIR.parent / "2-2" / "assets" / "forced-browse-download.txt"

_FILE_EXT_HINT = frozenset(
    {
        "bak", "old", "backup", "zip", "tar", "gz", "sql", "rar", "7z", "log",
        "env", "swp", "tmp", "copy", "orig", "save",
    }
)
_TEST_SEGMENTS = frozenset({"test", "demo", "debug", "staging", "dev", "tmp", "temp"})




def collect_base_urls(raw_config: dict[str, Any] | None) -> list[str]:
    deduped, _ = dedupe_probe_bases(collect_probe_base_urls(raw_config))
    return deduped


def _normalize_file_path(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("http://") or line.startswith("https://"):
        parsed = urlparse(line)
        return parsed.path or "/"
    return line if line.startswith("/") else f"/{line}"


def _load_wordlist_paths() -> tuple[list[str], dict[str, Any]]:
    seen: set[str] = set()
    paths: list[str] = []
    sources: list[str] = []

    for file_path in (_ASSETS, _FORCED_BROWSE):
        if not file_path.is_file():
            continue
        before = len(paths)
        for line in file_path.read_text(encoding="utf-8").splitlines():
            p = _normalize_file_path(line)
            if p is None or p in seen:
                continue
            # 3-6: file-like paths only (has dot or test segment)
            seg = p.rstrip("/").split("/")[-1]
            if "." not in seg and seg.lower() not in _TEST_SEGMENTS:
                continue
            seen.add(p)
            paths.append(p)
        if len(paths) > before:
            sources.append(file_path.name)

    meta = {
        "wordlist_files": sources,
        "wordlist_total": len(paths),
    }
    return paths, meta


def _normalize_base(url: str) -> str:
    return url.rstrip("/").lower()


def _endpoint_path(ep: Endpoint) -> str:
    path, _ = split_path_query(ep.path)
    return path or "/"


def _looks_like_file_path(path: str) -> bool:
    path = path.split("?")[0]
    seg = path.rstrip("/").split("/")[-1].lower()
    if not seg:
        return False
    if seg in _TEST_SEGMENTS:
        return True
    if "." in seg:
        ext = seg.rsplit(".", 1)[-1]
        if ext in _FILE_EXT_HINT:
            return True
        if seg.endswith((".bak", ".old", ".backup", ".sql", ".zip", ".env")):
            return True
    return False


def _select_file_paths(endpoints: list[Endpoint], limit: int) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for ep in endpoints:
        path = _endpoint_path(ep)
        if not _looks_like_file_path(path):
            continue
        if path in seen:
            continue
        seen.add(path)
        paths.append(path)
    paths.sort()
    if limit <= 0 or len(paths) <= limit:
        return paths
    step = max(1, len(paths) // limit)
    picked = [paths[i] for i in range(0, len(paths), step)][:limit]
    return picked


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
    probe_mode: ProbeMode = "base_only",
    sample_size: int = 20,
    extra_paths: list[str] | None = None,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    bases = collect_base_urls(raw_config)
    wordlist, wl_meta = _load_wordlist_paths()
    meta: dict[str, Any] = {
        "probe_mode": probe_mode,
        "sample_size": sample_size,
        "base_urls": len(bases),
        **wl_meta,
        "inventory_endpoints": 0,
        "inventory_paths_added": 0,
        "inventory_fallback": False,
    }
    if not bases:
        return [], meta

    file_paths: set[str] = set(wordlist)
    wordlist_set = set(wordlist)

    for raw in extra_paths or []:
        p = _normalize_file_path(raw)
        if p:
            file_paths.add(p)

    if probe_mode in ("sample", "full"):
        tree = load_api_tree(data_dir)
        if tree and tree.endpoints:
            meta["inventory_endpoints"] = len(tree.endpoints)
            grouped = _inventory_by_base(tree, bases)
            before = len(file_paths)
            for _base, endpoints in grouped.items():
                limit = sample_size if probe_mode == "sample" else 0
                for p in _select_file_paths(endpoints, limit):
                    file_paths.add(p)
            meta["inventory_paths_added"] = len(file_paths) - before
        else:
            meta["inventory_fallback"] = True

    out: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    for base in bases:
        probe_base = probe_base_url(base)
        for path in sorted(file_paths):
            url = f"{probe_base.rstrip('/')}{path if path.startswith('/') else f'/{path}'}"
            if url in seen_urls:
                continue
            seen_urls.add(url)
            src = "wordlist" if path in wordlist_set else "inventory"
            out.append(
                {
                    "base_url": base,
                    "probe_url": url,
                    "label": f"{base}{path}",
                    "path": path,
                    "source": src,
                }
            )

    meta["targets"] = len(out)
    return out, meta
