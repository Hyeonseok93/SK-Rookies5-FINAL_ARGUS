"""File-backed ARGUS users (users.json) + JWT helpers."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.workspace import USERS_FILE, ROOT_DATA, user_data_dir

logger = logging.getLogger(__name__)

JWT_ALG = "HS256"
JWT_TTL_HOURS = 24
PASSWORD_MASK = "********"


def _jwt_secret() -> str:
    from app.runtime_env import require_secret

    secret = require_secret("JWT_SECRET", min_len=32)
    if not secret:
        secret = "argus-dev-jwt-secret-change-me-32b"
        logger.warning("JWT_SECRET unset; using insecure development secret")
    return secret


def _load_raw() -> dict[str, Any]:
    ROOT_DATA.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.is_file():
        return {"users": []}
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"users": []}


def _save_raw(payload: dict[str, Any]) -> None:
    ROOT_DATA.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def list_users() -> list[dict[str, Any]]:
    return list(_load_raw().get("users") or [])


def find_user_by_username(username: str) -> dict[str, Any] | None:
    needle = username.strip().lower()
    for user in list_users():
        if str(user.get("username", "")).strip().lower() == needle:
            return user
    return None


def find_user_by_id(user_id: str) -> dict[str, Any] | None:
    for user in list_users():
        if str(user.get("id")) == user_id:
            return user
    return None


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        return False


def create_user(username: str, password: str) -> dict[str, Any]:
    username = username.strip()
    if len(username) < 3:
        raise ValueError("username must be at least 3 characters")
    if len(password) < 6:
        raise ValueError("password must be at least 6 characters")
    if find_user_by_username(username):
        raise ValueError("username already taken")

    user = {
        "id": uuid.uuid4().hex,
        "username": username,
        "password_hash": hash_password(password),
        "created_at": datetime.now(UTC).isoformat(),
    }
    payload = _load_raw()
    users = list(payload.get("users") or [])
    users.append(user)
    payload["users"] = users
    _save_raw(payload)
    user_data_dir(user["id"])
    return {"id": user["id"], "username": user["username"], "created_at": user["created_at"]}


def issue_token(user: dict[str, Any]) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "iat": now,
        "exp": now + timedelta(hours=JWT_TTL_HOURS),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALG)


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, _jwt_secret(), algorithms=[JWT_ALG])


def public_user(user: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(user["id"]),
        "username": str(user["username"]),
        "created_at": str(user.get("created_at") or ""),
    }


def bootstrap_admin_if_needed() -> None:
    if list_users():
        return
    username = (os.environ.get("ADMIN_USERNAME") or "").strip()
    password = (os.environ.get("ADMIN_PASSWORD") or "").strip()
    if not username or not password:
        logger.info("No users yet and ADMIN_USERNAME/ADMIN_PASSWORD unset; skipping bootstrap")
        return
    try:
        create_user(username, password)
        logger.info("Bootstrapped admin user %s", username)
    except ValueError as exc:
        logger.warning("Admin bootstrap skipped: %s", exc)
