"""Thread-safe diagnosis auth sessions with proactive refresh before JWT expiry."""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_REFRESH_MARGIN_SEC = 300


def jwt_expiry_epoch(token: str) -> float | None:
    """Return JWT ``exp`` claim as Unix epoch seconds, or None."""
    try:
        raw = str(token or "").strip()
        if raw.startswith("Bearer "):
            raw = raw[7:].strip()
        parts = raw.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        pad = "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload + pad))
        exp = data.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


def session_expiry_epoch(session: dict[str, Any]) -> float | None:
    for key in ("access_token", "token"):
        value = str(session.get(key) or "").strip()
        if value:
            exp = jwt_expiry_epoch(value)
            if exp is not None:
                return exp
    return None


def earliest_session_expiry(sessions: list[dict[str, Any]]) -> float | None:
    exps = [exp for session in sessions if (exp := session_expiry_epoch(session)) is not None]
    return min(exps) if exps else None


def resolve_refresh_margin_sec(raw_config: dict[str, Any] | None) -> int:
    cfg = (raw_config or {}).get("diagnosis_auth") or {}
    try:
        value = int(cfg.get("refresh_margin_sec", DEFAULT_REFRESH_MARGIN_SEC))
    except (TypeError, ValueError):
        value = DEFAULT_REFRESH_MARGIN_SEC
    return max(60, min(value, 3600))


class DiagnosisAuthPool:
    """Live login sessions for long-running diagnosis probes."""

    def __init__(
        self,
        raw_config: dict[str, Any] | None,
        *,
        data_dir: Path | None = None,
        refresh_margin_sec: int | None = None,
        refresh_on_start: bool = True,
    ) -> None:
        self._raw = raw_config or {}
        self._data_dir = data_dir
        self._margin = (
            margin_sec
            if (margin_sec := refresh_margin_sec) is not None
            else resolve_refresh_margin_sec(self._raw)
        )
        self._lock = threading.Lock()
        self._sessions: list[dict[str, Any]] = []
        self._meta: dict[str, Any] = {"source": "none", "sessions": 0}
        self._refresh_count = 0
        if refresh_on_start:
            self.refresh()

    @property
    def meta(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._meta)

    @property
    def refresh_count(self) -> int:
        with self._lock:
            return self._refresh_count

    def sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._sessions)

    def primary(self) -> dict[str, Any] | None:
        sessions = self.sessions()
        return sessions[0] if sessions else None

    def refresh(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        from diagnosis.probe_auth import all_account_auths_with_meta

        sessions, meta = all_account_auths_with_meta(
            self._raw,
            data_dir=self._data_dir,
            refresh=True,
        )
        with self._lock:
            self._sessions = sessions
            self._meta = meta
            self._refresh_count += 1
        if sessions:
            logger.info(
                "diagnosis auth refreshed (%s session(s), source=%s)",
                len(sessions),
                meta.get("source"),
            )
        return sessions, meta

    def needs_refresh(self, *, now: float | None = None) -> bool:
        with self._lock:
            sessions = self._sessions
        if not sessions:
            return False
        min_exp = earliest_session_expiry(sessions)
        if min_exp is None:
            return False
        ts = time.time() if now is None else now
        return ts + self._margin >= min_exp

    def ensure_valid(self) -> bool:
        """Refresh when any session expires within the configured margin."""
        if not self.needs_refresh():
            return False
        self.refresh()
        return True
