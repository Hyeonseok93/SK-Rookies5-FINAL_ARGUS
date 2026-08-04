"""FastAPI dependencies: JWT auth + per-user workspace."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth_users import decode_token, find_user_by_id, public_user
from app.workspace import bind_workspace, reset_workspace, user_data_dir

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, Any]:
    if creds is None or creds.scheme.lower() != "bearer" or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(creds.credentials)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    user_id = str(payload.get("sub") or "")
    user = find_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return public_user(user)


async def get_user_data_dir(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> AsyncGenerator[Path, None]:
    """Bind workspace in the asyncio context (not a worker thread)."""
    path = user_data_dir(user["id"])
    tokens = bind_workspace(user_id=user["id"], data_dir=path)
    try:
        yield path
    finally:
        reset_workspace(tokens)


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]
UserDataDir = Annotated[Path, Depends(get_user_data_dir)]
