"""Load 2-2 replay helpers from diagnosis/modules/2-2/replay/ (folder 2-2 is not a package)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

_REPLAY_DIR = Path(__file__).resolve().parent / "modules" / "2-2" / "replay"
_CACHE: dict[str, Any] = {}


def load(name: str) -> Any:
    cached = _CACHE.get(name)
    if cached is not None:
        return cached
    path = _REPLAY_DIR / f"{name}.py"
    mod_name = f"diag_g22_replay_{name}"
    if mod_name in sys.modules:
        mod = sys.modules[mod_name]
        _CACHE[name] = mod
        return mod
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load 2-2 replay module: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    _CACHE[name] = mod
    return mod


def perform_login(*args: Any, **kwargs: Any):
    return load("browser_auth").perform_login(*args, **kwargs)


def match_ui_flow(*args: Any, **kwargs: Any):
    return load("ui_flows").match_ui_flow(*args, **kwargs)


def ui_flow_to_replay_steps(*args: Any, **kwargs: Any):
    return load("ui_flows").ui_flow_to_replay_steps(*args, **kwargs)


def G22ReplaySession(*args: Any, **kwargs: Any):
    return load("session").G22ReplaySession(*args, **kwargs)


def resolve_spa_browser_session(*args: Any, **kwargs: Any):
    return load("spa_browser_session").resolve_spa_browser_session(*args, **kwargs)


def browser_full_cookie_pairs(*args: Any, **kwargs: Any):
    return load("spa_browser_session").browser_full_cookie_pairs(*args, **kwargs)


def unwrap_login_payload(*args: Any, **kwargs: Any):
    return load("spa_browser_session").unwrap_login_payload(*args, **kwargs)


def playwright_cookies_from_login(*args: Any, **kwargs: Any):
    return load("spa_browser_session").playwright_cookies_from_login(*args, **kwargs)


def spa_browser_session_mod() -> Any:
    """Return the 2-2 spa_browser_session module (classes live here)."""
    return load("spa_browser_session")
