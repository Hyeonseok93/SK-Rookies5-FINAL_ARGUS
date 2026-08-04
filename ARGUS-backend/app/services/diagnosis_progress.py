"""In-memory progress for long-running diagnosis module runs (per-user)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from app.workspace import current_user_id

_lock = threading.Lock()
_states: dict[str, dict[str, Any]] = {}
_cancel_events: dict[str, threading.Event] = {}


def _uid(user_id: str | None = None) -> str:
    uid = user_id or current_user_id()
    if not uid:
        raise RuntimeError("diagnosis progress user_id is not bound")
    return uid


def _default_state() -> dict[str, Any]:
    return {
        "running": False,
        "section_id": None,
        "phase": "",
        "message": "",
        "endpoints_done": 0,
        "endpoints_total": 0,
        "requests_sent": 0,
        "requests_cap": None,
        "percent": 0,
        "updated_at": None,
    }


def _ensure(user_id: str) -> tuple[dict[str, Any], threading.Event]:
    with _lock:
        if user_id not in _states:
            _states[user_id] = _default_state()
        if user_id not in _cancel_events:
            _cancel_events[user_id] = threading.Event()
        return _states[user_id], _cancel_events[user_id]


def _compute_percent(
    *,
    phase: str,
    endpoints_done: int,
    endpoints_total: int,
) -> int:
    if phase == "done":
        return 100
    if phase in ("error", "cancelled"):
        return 0
    if phase == "cancelling":
        if endpoints_total > 0:
            return min(99, int(endpoints_done * 100 / endpoints_total))
        return 5
    if phase in ("zap", "zap_supplemental"):
        if endpoints_total > 0 and endpoints_done >= endpoints_total:
            return 95
        return 90
    if phase in ("preparing", "starting"):
        return 2
    if phase in ("analyzing", "inventory"):
        return 50 if endpoints_total <= 0 else min(99, int(endpoints_done * 100 / endpoints_total))
    if endpoints_total > 0:
        return min(99, int(endpoints_done * 100 / endpoints_total))
    if phase in ("httpx", "probe", "httpx_pii", "httpx_fuzz", "running"):
        return 10
    return 0


def is_cancel_requested(user_id: str | None = None) -> bool:
    uid = _uid(user_id)
    _, event = _ensure(uid)
    return event.is_set()


def request_cancel(*, message: str = "취소 요청됨…", user_id: str | None = None) -> None:
    uid = _uid(user_id)
    _, event = _ensure(uid)
    event.set()
    update(phase="cancelling", message=message, user_id=uid)


def reset(
    *,
    section_id: str,
    endpoints_total: int = 0,
    message: str = "Starting…",
    user_id: str | None = None,
) -> None:
    uid = _uid(user_id)
    state, event = _ensure(uid)
    event.clear()
    with _lock:
        state.update(
            {
                "running": True,
                "section_id": section_id,
                "phase": "starting",
                "message": message,
                "endpoints_done": 0,
                "endpoints_total": max(0, int(endpoints_total)),
                "requests_sent": 0,
                "requests_cap": None,
                "percent": _compute_percent(
                    phase="starting",
                    endpoints_done=0,
                    endpoints_total=max(0, int(endpoints_total)),
                ),
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )


def update(
    *,
    phase: str | None = None,
    message: str | None = None,
    endpoints_done: int | None = None,
    endpoints_total: int | None = None,
    requests_sent: int | None = None,
    requests_cap: int | None = None,
    percent: int | None = None,
    running: bool | None = None,
    user_id: str | None = None,
) -> None:
    uid = _uid(user_id)
    state, _ = _ensure(uid)
    with _lock:
        if running is not None:
            state["running"] = bool(running)
        if phase is not None:
            state["phase"] = phase
        if message is not None:
            state["message"] = message
        if endpoints_done is not None:
            state["endpoints_done"] = max(0, int(endpoints_done))
        if endpoints_total is not None:
            state["endpoints_total"] = max(0, int(endpoints_total))
        if requests_sent is not None:
            state["requests_sent"] = max(0, int(requests_sent))
        if requests_cap is not None:
            state["requests_cap"] = requests_cap if requests_cap > 0 else None
        if percent is not None:
            state["percent"] = min(99, max(0, int(percent)))
        else:
            state["percent"] = _compute_percent(
                phase=str(state.get("phase") or ""),
                endpoints_done=int(state.get("endpoints_done") or 0),
                endpoints_total=int(state.get("endpoints_total") or 0),
            )
        state["updated_at"] = datetime.now(UTC).isoformat()


def finish(message: str = "Done", user_id: str | None = None) -> None:
    uid = _uid(user_id)
    state, event = _ensure(uid)
    event.clear()
    with _lock:
        state["running"] = False
        state["phase"] = "done"
        state["message"] = message
        state["percent"] = 100
        state["updated_at"] = datetime.now(UTC).isoformat()


def cancel_finish(message: str = "Cancelled", user_id: str | None = None) -> None:
    uid = _uid(user_id)
    state, event = _ensure(uid)
    event.clear()
    with _lock:
        state["running"] = False
        state["phase"] = "cancelled"
        state["message"] = message
        state["updated_at"] = datetime.now(UTC).isoformat()


def fail(message: str, user_id: str | None = None) -> None:
    uid = _uid(user_id)
    state, event = _ensure(uid)
    event.clear()
    with _lock:
        state["running"] = False
        state["phase"] = "error"
        state["message"] = message
        state["updated_at"] = datetime.now(UTC).isoformat()


def snapshot(user_id: str | None = None) -> dict[str, Any]:
    uid = _uid(user_id)
    state, _ = _ensure(uid)
    with _lock:
        return dict(state)
