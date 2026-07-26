"""In-memory progress for long-running diagnosis module runs."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

_lock = threading.Lock()
_cancel_event = threading.Event()
_state: dict[str, Any] = {
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


def is_cancel_requested() -> bool:
    return _cancel_event.is_set()


def request_cancel(*, message: str = "취소 요청됨…") -> None:
    _cancel_event.set()
    update(phase="cancelling", message=message)


def reset(*, section_id: str, endpoints_total: int = 0, message: str = "Starting…") -> None:
    _cancel_event.clear()
    with _lock:
        _state.update(
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
) -> None:
    with _lock:
        if running is not None:
            _state["running"] = bool(running)
        if phase is not None:
            _state["phase"] = phase
        if message is not None:
            _state["message"] = message
        if endpoints_done is not None:
            _state["endpoints_done"] = max(0, int(endpoints_done))
        if endpoints_total is not None:
            _state["endpoints_total"] = max(0, int(endpoints_total))
        if requests_sent is not None:
            _state["requests_sent"] = max(0, int(requests_sent))
        if requests_cap is not None:
            _state["requests_cap"] = requests_cap if requests_cap > 0 else None
        if percent is not None:
            _state["percent"] = min(99, max(0, int(percent)))
        else:
            _state["percent"] = _compute_percent(
                phase=str(_state.get("phase") or ""),
                endpoints_done=int(_state.get("endpoints_done") or 0),
                endpoints_total=int(_state.get("endpoints_total") or 0),
            )
        _state["updated_at"] = datetime.now(UTC).isoformat()


def finish(message: str = "Done") -> None:
    _cancel_event.clear()
    with _lock:
        _state["running"] = False
        _state["phase"] = "done"
        _state["message"] = message
        _state["percent"] = 100
        _state["updated_at"] = datetime.now(UTC).isoformat()


def cancel_finish(message: str = "Cancelled") -> None:
    _cancel_event.clear()
    with _lock:
        _state["running"] = False
        _state["phase"] = "cancelled"
        _state["message"] = message
        _state["updated_at"] = datetime.now(UTC).isoformat()


def fail(message: str) -> None:
    _cancel_event.clear()
    with _lock:
        _state["running"] = False
        _state["phase"] = "error"
        _state["message"] = message
        _state["updated_at"] = datetime.now(UTC).isoformat()


def snapshot() -> dict[str, Any]:
    with _lock:
        return dict(_state)
