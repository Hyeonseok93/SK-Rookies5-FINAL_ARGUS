"""Select guideline 1-3 scan candidates from an ApiTree (generic — 2-2 pattern)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inventory.schema import ApiTree, Endpoint

import importlib.util

_MODULE_DIR = Path(__file__).resolve().parent


def _load_param_classify():
    spec = importlib.util.spec_from_file_location("diag_g13_param_classify", _MODULE_DIR / "param_classify.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load 1-3 param_classify")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["diag_g13_param_classify"] = mod
    spec.loader.exec_module(mod)
    return mod


_pc = _load_param_classify()

WRITE_METHODS = ("POST", "PUT", "PATCH")


def sensitive_params(ep: Endpoint, *, assets_dir: Path) -> list[tuple[Any, str, str]]:
    """(input_param, category, reason) for every request param that classifies as sensitive."""
    out: list[tuple[Any, str, str]] = []
    for inp in ep.request_params:
        if inp.in_ not in ("query", "body", "form") or inp.role != "input":
            continue
        result = _pc.classify_param_name(inp.name, assets_dir=assets_dir)
        if result is not None:
            category, reason = result
            out.append((inp, category, reason))
    return out


def score_candidate(ep: Endpoint, *, assets_dir: Path) -> int:
    score = 0
    if ep.method.upper() in WRITE_METHODS:
        score += 1
    score += 3 * len(sensitive_params(ep, assets_dir=assets_dir))
    return score


def is_candidate(ep: Endpoint, *, assets_dir: Path, min_score: int = 2) -> bool:
    return score_candidate(ep, assets_dir=assets_dir) >= min_score


def select_scan_targets(
    tree: ApiTree,
    *,
    assets_dir: Path,
    min_score: int = 2,
    max_count: int = 0,
    scan_all_inventory: bool = False,
) -> tuple[list[Endpoint], str]:
    """Returns (endpoints, mode) — mode is 'scored_api' or 'all_inventory'."""
    if scan_all_inventory:
        ranked = sorted(
            tree.endpoints,
            key=lambda e: (-score_candidate(e, assets_dir=assets_dir), e.base_url, e.path, e.method.upper()),
        )
        return ranked, "all_inventory"

    scored: list[tuple[int, Endpoint]] = []
    for ep in tree.endpoints:
        if ep.kind != "api":
            continue
        sc = score_candidate(ep, assets_dir=assets_dir)
        if sc >= min_score:
            scored.append((sc, ep))
    scored.sort(key=lambda x: (-x[0], x[1].base_url, x[1].path, x[1].method))
    selected = [ep for _, ep in scored]
    if max_count > 0:
        selected = selected[:max_count]
    return selected, "scored_api"


def candidate_summary(candidates: list[Endpoint], *, mode: str = "scored_api") -> dict[str, Any]:
    return {
        "total": len(candidates),
        "mode": mode,
        "by_method": _count_by(candidates, lambda e: e.method.upper()),
        "by_base": _count_by(candidates, lambda e: e.base_url),
    }


def _count_by(items: list[Endpoint], key_fn: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = str(key_fn(item))
        out[k] = out.get(k, 0) + 1
    return out
