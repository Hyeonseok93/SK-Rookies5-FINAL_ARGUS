"""In-memory + file progress for long-running ZAP discover."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_lock = threading.Lock()
_state: dict[str, Any] = {
    "running": False,
    "phase": "",
    "message": "",
    "step": 0,
    "total_steps": 0,
    "updated_at": None,
}


def reset(total_steps: int = 6) -> None:
    with _lock:
        _state.update(
            {
                "running": True,
                "phase": "starting",
                "message": "Starting ZAP discover…",
                "step": 0,
                "total_steps": total_steps,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )


def update(*, phase: str, message: str, step: int | None = None) -> None:
    with _lock:
        _state["phase"] = phase
        _state["message"] = message
        if step is not None:
            _state["step"] = step
        _state["updated_at"] = datetime.now(UTC).isoformat()


def finish(message: str = "Done") -> None:
    with _lock:
        _state["running"] = False
        _state["phase"] = "done"
        _state["message"] = message
        _state["updated_at"] = datetime.now(UTC).isoformat()


def fail(message: str) -> None:
    with _lock:
        _state["running"] = False
        _state["phase"] = "error"
        _state["message"] = message
        _state["updated_at"] = datetime.now(UTC).isoformat()


def snapshot() -> dict[str, Any]:
    with _lock:
        return dict(_state)


def persist(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "discover-progress.json"
    path.write_text(json.dumps(snapshot(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
