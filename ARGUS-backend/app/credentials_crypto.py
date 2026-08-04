"""Encrypt diagnostic target credentials at rest (Fernet)."""

from __future__ import annotations

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_PREFIX = "enc:"


def _fernet() -> Fernet:
    from app.runtime_env import require_secret

    raw = require_secret("CREDENTIALS_KEY", min_len=16)
    if not raw:
        raw = (os.environ.get("JWT_SECRET") or "").strip()
    if not raw:
        raw = "argus-dev-credentials-key-change-me"
        logger.warning("CREDENTIALS_KEY/JWT_SECRET unset; using insecure development key")
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    if plaintext.startswith(_PREFIX):
        return plaintext
    token = _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
    return f"{_PREFIX}{token}"


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    if not value.startswith(_PREFIX):
        # Legacy plaintext on disk
        return value
    token = value[len(_PREFIX) :]
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt credential; returning empty string")
        return ""


def mask_secret(value: str) -> str:
    if not value:
        return ""
    return "********"
