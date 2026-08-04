"""Per-user workspace roots under data/users/{user_id}/."""

from __future__ import annotations

from contextvars import ContextVar, Token
from pathlib import Path

from app.config import BACKEND_ROOT

ROOT_DATA = BACKEND_ROOT / "data"
USERS_DIR = ROOT_DATA / "users"
USERS_FILE = ROOT_DATA / "users.json"

_bound_data_dir: ContextVar[Path | None] = ContextVar("argus_bound_data_dir", default=None)
_bound_user_id: ContextVar[str | None] = ContextVar("argus_bound_user_id", default=None)


def user_data_dir(user_id: str) -> Path:
    """Return (and create) the isolated workspace for a user."""
    safe = "".join(ch for ch in str(user_id) if ch.isalnum() or ch in "-_")
    if not safe or safe != str(user_id):
        raise ValueError("invalid user id")
    path = USERS_DIR / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def bind_workspace(*, user_id: str | None = None, data_dir: Path | None = None) -> tuple[Token, Token]:
    """Bind current request/run workspace for services that still omit data_dir."""
    t_user = _bound_user_id.set(user_id)
    t_dir = _bound_data_dir.set(data_dir)
    return t_user, t_dir


def reset_workspace(tokens: tuple[Token, Token]) -> None:
    _bound_user_id.reset(tokens[0])
    _bound_data_dir.reset(tokens[1])


def current_user_id() -> str | None:
    return _bound_user_id.get()


def current_data_dir() -> Path | None:
    return _bound_data_dir.get()


def require_data_dir(data_dir: Path | None = None) -> Path:
    resolved = data_dir if data_dir is not None else current_data_dir()
    if resolved is None:
        raise RuntimeError("workspace data_dir is not bound")
    return resolved
