"""ARGUS redirect sink — receives open-redirect probes (1-5)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.deps import CurrentUser
from app.services import redirect_sink_service as sink

router = APIRouter(tags=["redirect-sink"])


@router.get("/argus-redirect-sink/r/{run_id}/{probe_id}")
def redirect_sink_hit(run_id: str, probe_id: str) -> dict[str, Any]:
    """Public hit endpoint — only records probes registered by an authenticated run."""
    payload = sink.record_hit(run_id, probe_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Unknown probe")
    return payload


@router.get("/api/argus-redirect-sink/hits")
def redirect_sink_hits(user: CurrentUser, limit: int = 50) -> dict[str, Any]:
    return sink.list_hits(user_id=user["id"], limit=limit)


@router.post("/api/argus-redirect-sink/register")
def redirect_sink_register(body: dict[str, Any], user: CurrentUser) -> dict[str, Any]:
    run_id = str(body.get("run_id") or "").strip()
    probe_ids = body.get("probe_ids") or []
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")
    if not isinstance(probe_ids, list):
        raise HTTPException(status_code=400, detail="probe_ids must be a list")
    count = sink.register_probes(
        user_id=user["id"],
        run_id=run_id,
        probe_ids=[str(p) for p in probe_ids],
    )
    return {"ok": True, "registered": count}
