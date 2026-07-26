"""Load 2-2 payload and wordlist assets."""

from __future__ import annotations

from pathlib import Path


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_traversal_payloads(assets_dir: Path, *, limit: int = 0) -> list[str]:
    items = _read_lines(assets_dir / "path-traversal-payloads.txt")
    if limit > 0:
        return items[:limit]
    return items


def load_forced_browse_paths(assets_dir: Path) -> list[str]:
    return _read_lines(assets_dir / "forced-browse-download.txt")
