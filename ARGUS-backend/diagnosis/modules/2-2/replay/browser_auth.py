"""2-2 SPA browser auth — re-exports config-driven cookie helpers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

_SPA_PATH = Path(__file__).resolve().parent / "spa_browser_session.py"
_SPA_MOD_NAME = "diag_g22_replay_spa_browser_session"


def _spa() -> Any:
    if _SPA_MOD_NAME in sys.modules:
        return sys.modules[_SPA_MOD_NAME]
    spec = importlib.util.spec_from_file_location(_SPA_MOD_NAME, _SPA_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {_SPA_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_SPA_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_spa_mod = _spa()
ONDE_COOKIE_NAMES = _spa_mod.ONDE_COOKIE_NAMES
SpaBrowserSessionConfig = _spa_mod.SpaBrowserSessionConfig
perform_login = _spa_mod.perform_login
playwright_cookies_from_login = _spa_mod.playwright_cookies_from_login
resolve_spa_browser_session = _spa_mod.resolve_spa_browser_session
unwrap_login_payload = _spa_mod.unwrap_login_payload
_unwrap_login_payload = _spa_mod.unwrap_login_payload
browser_full_cookie_pairs = _spa_mod.browser_full_cookie_pairs

__all__ = [
    "ONDE_COOKIE_NAMES",
    "SpaBrowserSessionConfig",
    "perform_login",
    "playwright_cookies_from_login",
    "resolve_spa_browser_session",
    "unwrap_login_payload",
    "_unwrap_login_payload",
    "browser_full_cookie_pairs",
]
