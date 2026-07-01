"""ARGUS redirect sink — receives open-redirect probes (1-5)."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter

router = APIRouter(tags=["redirect-sink"])

_hits: list[dict[str, Any]] = []
_MAX_HITS = 5000


@router.get("/argus-redirect-sink/r/{run_id}/{probe_id}")
def redirect_sink_hit(run_id: str, probe_id: str) -> dict[str, Any]:
    payload = {
        "ok": True,
        "run_id": run_id,
        "probe_id": probe_id,
        "ts": time.time(),
    }
    _hits.append(payload)
    if len(_hits) > _MAX_HITS:
        del _hits[: len(_hits) - _MAX_HITS]
    return payload


@router.get("/argus-redirect-sink/hits")
def redirect_sink_hits(limit: int = 50) -> dict[str, Any]:
    lim = max(1, min(limit, 200))
    return {"hits": _hits[-lim:], "total": len(_hits)}
