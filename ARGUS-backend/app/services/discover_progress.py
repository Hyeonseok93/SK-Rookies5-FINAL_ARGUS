"""In-memory + file progress for long-running ZAP discover (per-user)."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.workspace import current_user_id

_lock = threading.Lock()
_states: dict[str, dict[str, Any]] = {}


def _uid(user_id: str | None = None) -> str:
    uid = user_id or current_user_id()
    if not uid:
        raise RuntimeError("discover progress user_id is not bound")
    return uid


def _default_state() -> dict[str, Any]:
    return {
        "running": False,
        "phase": "",
        "message": "",
        "step": 0,
        "total_steps": 0,
        "updated_at": None,
    }


def _ensure(user_id: str) -> dict[str, Any]:
    with _lock:
        if user_id not in _states:
            _states[user_id] = _default_state()
        return _states[user_id]


def reset(total_steps: int = 6, user_id: str | None = None) -> None:
    uid = _uid(user_id)
    state = _ensure(uid)
    with _lock:
        state.update(
            {
                "running": True,
                "phase": "starting",
                "message": "Starting ZAP discover…",
                "step": 0,
                "total_steps": total_steps,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )


def update(
    *,
    phase: str,
    message: str,
    step: int | None = None,
    user_id: str | None = None,
) -> None:
    uid = _uid(user_id)
    state = _ensure(uid)
    with _lock:
        state["phase"] = phase
        state["message"] = message
        if step is not None:
            state["step"] = step
        state["updated_at"] = datetime.now(UTC).isoformat()


def finish(message: str = "Done", user_id: str | None = None) -> None:
    uid = _uid(user_id)
    state = _ensure(uid)
    with _lock:
        state["running"] = False
        state["phase"] = "done"
        state["message"] = message
        state["updated_at"] = datetime.now(UTC).isoformat()


def fail(message: str, user_id: str | None = None) -> None:
    uid = _uid(user_id)
    state = _ensure(uid)
    with _lock:
        state["running"] = False
        state["phase"] = "error"
        state["message"] = message
        state["updated_at"] = datetime.now(UTC).isoformat()


def snapshot(user_id: str | None = None) -> dict[str, Any]:
    uid = _uid(user_id)
    state = _ensure(uid)
    with _lock:
        return dict(state)


def persist(data_dir: Path, user_id: str | None = None) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "discover-progress.json"
    path.write_text(
        json.dumps(snapshot(user_id=user_id), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
