"""Select guideline 2-2 scan candidates from an ApiTree (generic)."""

from __future__ import annotations

import re
from typing import Any

from inventory.schema import ApiTree, Endpoint
from inventory.tags import PATH_LIKE_NAMES, PATH_LIKE_PATH, tag_endpoint

FILE_LIKE_PARAM = PATH_LIKE_NAMES
FILE_LIKE_PATH = PATH_LIKE_PATH


def is_file_like_param(name: str) -> bool:
    return bool(FILE_LIKE_PARAM.search(name or ""))


def score_candidate(ep: Endpoint) -> int:
    score = 0
    if "2-2-candidate" in ep.tags:
        score += 3
    if FILE_LIKE_PATH.search(ep.path):
        score += 4
    for inp in ep.request_params:
        if inp.in_ == "path" and inp.name not in ("id", "scheduleId", "bookingId"):
            if is_file_like_param(inp.name):
                score += 2
        elif inp.in_ in ("query", "body", "form") and is_file_like_param(inp.name):
            score += 3
    method = ep.method.upper()
    if method in ("GET", "POST") and any(k in ep.path.lower() for k in ("export", "download", "report", "attach")):
        score += 2
    return score


def is_candidate(ep: Endpoint, *, min_score: int = 2) -> bool:
    return score_candidate(ep) >= min_score


def prepare_tree(tree: ApiTree) -> ApiTree:
    for ep in tree.endpoints:
        tag_endpoint(ep)
    return tree


def select_candidates(
    tree: ApiTree,
    *,
    min_score: int = 2,
    max_count: int = 0,
    kinds: set[str] | None = None,
    scan_all_inventory: bool = False,
) -> list[Endpoint]:
    """Pick scan targets. Default: scored 2-2 API candidates, capped by max_count."""
    targets, _ = select_scan_targets(
        tree,
        min_score=min_score,
        max_count=max_count,
        kinds=kinds,
        scan_all_inventory=scan_all_inventory,
    )
    return targets


def select_scan_targets(
    tree: ApiTree,
    *,
    min_score: int = 2,
    max_count: int = 0,
    kinds: set[str] | None = None,
    scan_all_inventory: bool = False,
) -> tuple[list[Endpoint], str]:
    """
    Returns (endpoints, mode).

    mode:
      - ``scored_api`` — kind=api only, score >= min_score, top max_count by score
      - ``all_inventory`` — every row in api-tree (api + frontend), no score/limit cut
    """
    prepare_tree(tree)
    allowed = kinds or {"api"}

    if scan_all_inventory:
        ranked = sorted(tree.endpoints, key=_rank_key)
        return ranked, "all_inventory"

    scored: list[tuple[int, Endpoint]] = []
    for ep in tree.endpoints:
        if ep.kind not in allowed:
            continue
        sc = score_candidate(ep)
        if sc >= min_score:
            scored.append((sc, ep))
    scored.sort(key=lambda x: (-x[0], x[1].base_url, x[1].path, x[1].method))
    selected = [ep for _, ep in scored]
    if max_count > 0:
        selected = selected[:max_count]
    return selected, "scored_api"


def _rank_key(ep: Endpoint) -> tuple:
    return (-score_candidate(ep), ep.base_url, ep.path, ep.method.upper())


def candidate_summary(candidates: list[Endpoint], *, mode: str = "scored_api") -> dict[str, Any]:
    return {
        "total": len(candidates),
        "mode": mode,
        "by_method": _count_by(candidates, lambda e: e.method.upper()),
        "by_base": _count_by(candidates, lambda e: e.base_url),
        "by_kind": _count_by(candidates, lambda e: e.kind),
    }


def _count_by(items: list[Endpoint], key_fn: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = str(key_fn(item))
        out[k] = out.get(k, 0) + 1
    return out
