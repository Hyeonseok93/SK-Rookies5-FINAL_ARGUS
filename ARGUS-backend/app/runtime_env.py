"""Runtime environment helpers (fail-closed secrets, feature flags)."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def is_production() -> bool:
    env = (os.environ.get("ARGUS_ENV") or os.environ.get("ENVIRONMENT") or "").strip().lower()
    if env in {"prod", "production"}:
        return True
    # Docker/AWS compose typically set this for real deploys
    if (os.environ.get("ARGUS_FAIL_CLOSED_SECRETS") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True
    return False


def public_register_allowed() -> bool:
    """Open registration is opt-in. Default: allow only outside production."""
    raw = (os.environ.get("ARGUS_ALLOW_PUBLIC_REGISTER") or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return not is_production()


def require_secret(name: str, *, min_len: int = 32) -> str:
    value = (os.environ.get(name) or "").strip()
    if value and len(value) >= min_len:
        return value
    if is_production():
        raise RuntimeError(
            f"{name} must be set to a strong value (>= {min_len} chars) in production"
        )
    if value:
        logger.warning("%s is shorter than %d chars; using anyway in non-production", name, min_len)
        return value
    return ""
