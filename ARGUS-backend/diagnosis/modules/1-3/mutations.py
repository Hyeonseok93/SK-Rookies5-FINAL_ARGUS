"""Mutation value sets for guideline 1-3 (SCOPE.md §5 mutation table).

Static sets (PRICE/PRIVILEGE/STATUS/ENUM) come from assets/mutation-values.yaml.
IDOR is generated dynamically from the original value, same idea as
ARGUS_Backend/scanners/param_manipulation/manipulator.py:_get_payloads.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

STATIC_CATEGORIES = ("PRICE", "PRIVILEGE", "STATUS", "ENUM")

# Hidden-candidate probe: try adding a field the client never sends (SCOPE §5 "hidden test").
EXTRA_FIELD_PROBES: list[tuple[str, Any, str]] = [
    ("isAdmin", True, "hidden 필드 추가: isAdmin=true 주입"),
]


@lru_cache(maxsize=1)
def _load_static_values(assets_dir_str: str) -> dict[str, list[tuple[str, str]]]:
    path = Path(assets_dir_str) / "mutation-values.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, list[tuple[str, str]]] = {}
    for category, entries in raw.items():
        out[category] = [(str(v), str(desc)) for v, desc in entries]
    return out


def _idor_mutations(original_value: Any) -> list[tuple[str, str]]:
    try:
        base_id = int(str(original_value))
    except (TypeError, ValueError):
        return []
    return [
        ("0", "ID 0 (경계값)"),
        ("-1", f"ID {base_id - 1} (원본-1)" if base_id - 1 != -1 else "ID -1 (음수)"),
        ("999999", "ID 극대값"),
        (str(base_id + 1), f"ID {base_id + 1} (원본+1)"),
    ]


def mutations_for(category: str, original_value: Any, *, assets_dir: Path) -> list[tuple[str, str]]:
    """Return [(mutated_value, description), ...] for a classified parameter."""
    if category == "IDOR":
        return _idor_mutations(original_value)
    if category in STATIC_CATEGORIES:
        return _load_static_values(str(assets_dir)).get(category, [])
    return []
