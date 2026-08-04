"""Open-redirect sink probe registry + hits (1-5)."""

from __future__ import annotations

import threading
import time
from typing import Any

_lock = threading.Lock()
# probe_key -> {user_id, run_id, probe_id, registered_at}
_registry: dict[str, dict[str, Any]] = {}
# user_id -> list of hits
_hits_by_user: dict[str, list[dict[str, Any]]] = {}
_MAX_HITS = 5000


def _key(run_id: str, probe_id: str) -> str:
    return f"{run_id}:{probe_id}"


def register_probe(*, user_id: str, run_id: str, probe_id: str) -> None:
    with _lock:
        _registry[_key(run_id, probe_id)] = {
            "user_id": user_id,
            "run_id": run_id,
            "probe_id": probe_id,
            "registered_at": time.time(),
        }


def register_probes(*, user_id: str, run_id: str, probe_ids: list[str]) -> int:
    count = 0
    for probe_id in probe_ids:
        pid = str(probe_id or "").strip()
        if not pid:
            continue
        register_probe(user_id=user_id, run_id=run_id, probe_id=pid)
        count += 1
    return count


def record_hit(run_id: str, probe_id: str) -> dict[str, Any] | None:
    """Record a sink hit if the probe was registered. Returns payload or None."""
    key = _key(run_id, probe_id)
    with _lock:
        meta = _registry.get(key)
        if not meta:
            return None
        user_id = str(meta["user_id"])
        payload = {
            "ok": True,
            "run_id": run_id,
            "probe_id": probe_id,
            "ts": time.time(),
        }
        bucket = _hits_by_user.setdefault(user_id, [])
        bucket.append(payload)
        if len(bucket) > _MAX_HITS:
            del bucket[: len(bucket) - _MAX_HITS]
        return payload


def list_hits(*, user_id: str, limit: int = 50) -> dict[str, Any]:
    lim = max(1, min(limit, 200))
    with _lock:
        hits = list(_hits_by_user.get(user_id) or [])
    return {"hits": hits[-lim:], "total": len(hits)}
