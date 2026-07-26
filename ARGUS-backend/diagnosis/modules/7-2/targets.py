"""Collect directory-listing probe targets for 7-2."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls as collect_base_urls
from inventory.schema import ApiTree, Endpoint, build_full_url, split_path_query
from inventory.load import load_api_tree
from inventory.net import probe_base_url

ProbeMode = Literal["base_only", "sample", "full"]

_MODULE_DIR = Path(__file__).resolve().parent
_ASSETS_DIR = _MODULE_DIR / "assets"
_FORCED_BROWSE = _MODULE_DIR.parent / "2-2" / "assets" / "forced-browse-download.txt"

_SKIP_PATHS = frozenset({"/", ""})

# File extensions — skip as directory probe roots
_FILE_EXT = frozenset(
    {
        "html", "htm", "php", "asp", "aspx", "jsp", "js", "css", "json", "xml",
        "pdf", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "map",
        "zip", "tar", "gz", "sql", "env", "yaml", "yml", "md", "txt", "bak", "old",
        "log", "conf", "csv", "xlsx", "doc", "docx", "exe", "dll", "jar", "war",
    }
)




def _normalize_path_token(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    p = line if line.startswith("/") else f"/{line}"
    p = p.rstrip("/") or p
    if p in _SKIP_PATHS:
        return None
    return p


def _load_wordlist_files() -> tuple[list[str], list[str]]:
    """Load every assets/directory-wordlist*.txt (built-in, always on)."""
    paths: list[str] = []
    sources: list[str] = []
    seen: set[str] = set()
    for path in sorted(_ASSETS_DIR.glob("directory-wordlist*.txt")):
        count_before = len(paths)
        for line in path.read_text(encoding="utf-8").splitlines():
            p = _normalize_path_token(line)
            if p is None or p in seen:
                continue
            seen.add(p)
            paths.append(p)
        if len(paths) > count_before:
            sources.append(path.name)
    return paths, sources


def _load_forced_browse_dirs() -> list[str]:
    """Single-segment names from 2-2 forced-browse (uploads, files, …)."""
    out: list[str] = []
    seen: set[str] = set()
    if not _FORCED_BROWSE.is_file():
        return out
    for line in _FORCED_BROWSE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line or "." in line:
            continue
        p = f"/{line}"
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def load_wordlist() -> tuple[list[str], dict[str, Any]]:
    """
    Built-in comprehensive wordlist — no manual path input required.

    Merges: directory-wordlist*.txt + 2-2 forced-browse directory tokens.
    """
    paths, file_sources = _load_wordlist_files()
    seen = set(paths)
    fb_count = 0
    for p in _load_forced_browse_dirs():
        if p not in seen:
            seen.add(p)
            paths.append(p)
            fb_count += 1
    meta = {
        "wordlist_files": file_sources,
        "wordlist_from_files": len(paths) - fb_count,
        "wordlist_from_forced_browse": fb_count,
        "wordlist_total": len(paths),
    }
    return paths, meta


def _normalize_base(url: str) -> str:
    return url.rstrip("/").lower()


def _looks_like_directory_path(path: str) -> bool:
    path = path.split("?")[0] or "/"
    if path in _SKIP_PATHS:
        return False
    if path.endswith("/"):
        return True
    segment = path.rstrip("/").split("/")[-1]
    if not segment:
        return False
    if segment.startswith(".") and segment.count(".") >= 1:
        return True
    if "." in segment:
        ext = segment.rsplit(".", 1)[-1].lower()
        if ext in _FILE_EXT:
            return False
    return True


def _parent_directory_paths(path: str) -> list[str]:
    """From /api/v1/reports/export → /api/v1/reports, /api/v1, /api …"""
    path = path.split("?")[0].rstrip("/") or "/"
    if path in _SKIP_PATHS:
        return []
    parts = [p for p in path.split("/") if p]
    out: list[str] = []
    for i in range(len(parts), 0, -1):
        p = "/" + "/".join(parts[:i])
        if p not in _SKIP_PATHS:
            out.append(p)
    return out


def _endpoint_path(ep: Endpoint) -> str:
    path, _ = split_path_query(ep.path)
    return path or "/"


def _select_directory_paths(endpoints: list[Endpoint], limit: int) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for ep in endpoints:
        path = _endpoint_path(ep)
        candidates = [path] if _looks_like_directory_path(path) else []
        candidates.extend(_parent_directory_paths(path))
        for cand in candidates:
            norm = cand.rstrip("/") or cand
            if norm in seen:
                continue
            seen.add(norm)
            paths.append(norm)
    paths.sort(key=lambda p: (p.count("/"), p))
    if limit <= 0 or len(paths) <= limit:
        return paths
    picked = [paths[0]]
    step = max(1, len(paths) // limit)
    for i in range(step, len(paths), step):
        if len(picked) >= limit:
            break
        if paths[i] not in picked:
            picked.append(paths[i])
    if len(picked) < limit and paths[-1] not in picked:
        picked.append(paths[-1])
    return picked[:limit]


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


def _append_probe_variants(
    out: list[dict[str, str]],
    seen: set[str],
    *,
    base_url: str,
    probe_base: str,
    path: str,
    source: str,
    try_no_slash: bool,
) -> None:
    path = path if path.startswith("/") else f"/{path}"
    if path in _SKIP_PATHS:
        return

    variants: list[tuple[str, str]] = [(f"{path}/", "trailing_slash")]
    if try_no_slash and not path.endswith("/"):
        variants.append((path, "no_slash"))

    for suffix, variant in variants:
        url = f"{probe_base.rstrip('/')}{suffix}"
        if url in seen:
            continue
        seen.add(url)
        out.append(
            {
                "base_url": base_url,
                "probe_url": url,
                "label": f"{base_url}{suffix}",
                "source": source,
                "variant": variant,
            }
        )


def build_probe_targets(
    raw_config: dict[str, Any] | None,
    *,
    data_dir: Path | None = None,
    probe_mode: ProbeMode = "base_only",
    sample_size: int = 20,
    extra_paths: list[str] | None = None,
    use_extended_wordlist: bool = False,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    _ = use_extended_wordlist  # always comprehensive; kept for API compat
    bases = collect_base_urls(raw_config)
    wordlist, wl_meta = load_wordlist()
    meta: dict[str, Any] = {
        "probe_mode": probe_mode,
        "sample_size": sample_size,
        "base_urls": len(bases),
        "wordlist_paths": wl_meta["wordlist_total"],
        **wl_meta,
        "inventory_endpoints": 0,
        "inventory_paths_added": 0,
        "inventory_fallback": False,
    }
    if not bases:
        return [], meta

    out: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    wordlist_set = set(wordlist)

    dir_paths: set[str] = set(wordlist)
    for raw in extra_paths or []:
        p = _normalize_path_token(raw)
        if p:
            dir_paths.add(p)

    if probe_mode in ("sample", "full"):
        tree = load_api_tree(data_dir)
        if tree and tree.endpoints:
            meta["inventory_endpoints"] = len(tree.endpoints)
            grouped = _inventory_by_base(tree, bases)
            before = len(dir_paths)
            for _base, endpoints in grouped.items():
                limit = sample_size if probe_mode == "sample" else 0
                for p in _select_directory_paths(endpoints, limit):
                    dir_paths.add(p.rstrip("/") or p)
            meta["inventory_paths_added"] = len(dir_paths) - before
        else:
            meta["inventory_fallback"] = True

    for base in bases:
        probe_base = probe_base_url(base)
        for path in sorted(dir_paths):
            src = "wordlist" if path in wordlist_set else "inventory"
            _append_probe_variants(
                out,
                seen_urls,
                base_url=base,
                probe_base=probe_base,
                path=path,
                source=src,
                try_no_slash=True,
            )

    meta["targets"] = len(out)
    return out, meta
