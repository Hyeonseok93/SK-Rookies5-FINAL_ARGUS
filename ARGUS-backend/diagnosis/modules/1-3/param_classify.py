"""Rule-based sensitive-parameter classification for guideline 1-3.

Ported from ARGUS_Backend/scanners/param_manipulation/classifier.py's
regex fallback path (no LLM — see SCOPE.md v1 scope). Patterns live in
assets/sensitive-param-patterns.yaml so they can be tuned without touching code.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

# Most-specific categories first: ENUM/STATUS use narrow, exact field-name lists while
# PRICE/PRIVILEGE/IDOR use broad substrings ("pay", "level", camelCase "Id" suffix) that
# would otherwise shadow specific SCOPE.md examples (paymentStatus, coverageLevel, productId).
CATEGORY_ORDER = ("STATUS", "ENUM", "PRICE", "PRIVILEGE", "IDOR")


@lru_cache(maxsize=1)
def _load_rules(assets_dir_str: str) -> list[tuple[str, re.Pattern]]:
    path = Path(assets_dir_str) / "sensitive-param-patterns.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules: list[tuple[str, re.Pattern]] = []
    for category in CATEGORY_ORDER:
        for entry in raw.get(category) or []:
            pattern = str(entry["pattern"])
            flags = 0 if entry.get("case_sensitive") else re.IGNORECASE
            rules.append((category, re.compile(pattern, flags)))
    return rules


def classify_param_name(name: str, *, assets_dir: Path) -> tuple[str, str] | None:
    """Classify a parameter name into a risk category.

    Returns (category, reason) or None when no rule matches (SAFE).
    """
    if not name:
        return None
    for category, pattern in _load_rules(str(assets_dir)):
        if pattern.search(name):
            return category, f"규칙 기반: '{name}'이 {category} 패턴 매칭"
    return None
